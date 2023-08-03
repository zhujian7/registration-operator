package bootstrapcontroller

import (
	"bytes"
	"context"
	"fmt"
	"time"

	operatorv1client "open-cluster-management.io/api/client/operator/clientset/versioned/typed/operator/v1"
	operatorinformer "open-cluster-management.io/api/client/operator/informers/externalversions/operator/v1"
	operatorlister "open-cluster-management.io/api/client/operator/listers/operator/v1"
	"open-cluster-management.io/registration-operator/pkg/helpers"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

const tlsCertFile = "tls.crt"

// BootstrapControllerSyncInterval is exposed so that integration tests can crank up the constroller sync speed.
var BootstrapControllerSyncInterval = 5 * time.Minute

// bootstrapController watches bootstrap-hub-kubeconfig and hub-kubeconfig-secret secrets, if the bootstrap-hub-kubeconfig secret
// is changed with hub kube-apiserver ca or apiserver endpoints, or the hub-kubeconfig-secret secret is expired, this controller
// will make the klusterlet re-bootstrap to get the new hub kubeconfig from hub cluster by deleting the current hub kubeconfig
// secret and restart the klusterlet agents
type bootstrapController struct {
	kubeClient       kubernetes.Interface
	klusterletLister operatorlister.KlusterletLister
	klusterletClient operatorv1client.KlusterletInterface
	secretInformers  map[string]corev1informers.SecretInformer
}

// NewBootstrapController returns a bootstrapController
func NewBootstrapController(
	kubeClient kubernetes.Interface,
	klusterletClient operatorv1client.KlusterletInterface,
	klusterletInformer operatorinformer.KlusterletInformer,
	secretInformers map[string]corev1informers.SecretInformer,
	recorder events.Recorder) factory.Controller {
	controller := &bootstrapController{
		kubeClient:       kubeClient,
		klusterletClient: klusterletClient,
		klusterletLister: klusterletInformer.Lister(),
		secretInformers:  secretInformers,
	}
	return factory.New().WithSync(controller.sync).
		WithInformersQueueKeyFunc(bootstrapSecretQueueKeyFunc(controller.klusterletLister),
			secretInformers[helpers.HubKubeConfig].Informer(),
			secretInformers[helpers.BootstrapHubKubeConfig].Informer(),
			secretInformers[helpers.ExternalManagedKubeConfig].Informer()).
		ResyncEvery(BootstrapControllerSyncInterval).
		ToController("BootstrapController", recorder)
}

func (k *bootstrapController) sync(ctx context.Context, controllerContext factory.SyncContext) error {
	queueKey := controllerContext.QueueKey()
	if queueKey == "" {
		return nil
	}

	klog.V(4).Infof("Reconciling klusterlet kubeconfig secrets %q", queueKey)

	agentNamespace, klusterletName, err := cache.SplitMetaNamespaceKey(queueKey)
	if err != nil {
		// ignore bad format key
		return nil
	}

	// triggered by resync, checking whether the hub kubeconfig secret is expired
	if agentNamespace == "" && klusterletName == factory.DefaultQueueKey {
		klusterlets, err := k.klusterletLister.List(labels.Everything())
		if err != nil {
			return err
		}

		for _, klusterlet := range klusterlets {
			namespace := helpers.AgentNamespace(klusterlet)
			// enqueue the klusterlet to reconcile
			controllerContext.Queue().Add(fmt.Sprintf("%s/%s", namespace, klusterlet.Name))
		}

		return nil
	}

	// handle rebootstrap if the klusterlet is in rebootstrapping state
	klusterlet, err := k.klusterletLister.Get(klusterletName)
	if err != nil {
		return err
	}
	requeueFunc := func(duration time.Duration) {
		controllerContext.Queue().AddAfter(queueKey, duration)
	}
	if meta.IsStatusConditionTrue(klusterlet.Status.Conditions, helpers.KlusterletRebootstrapProgressing) {
		return k.processRebootstrap(ctx, agentNamespace, klusterletName, controllerContext.Recorder(), requeueFunc)
	}

	bootstrapHubKubeconfigSecret, err := k.secretInformers[helpers.BootstrapHubKubeConfig].Lister().Secrets(agentNamespace).Get(helpers.BootstrapHubKubeConfig)
	switch {
	case errors.IsNotFound(err):
		// the bootstrap hub kubeconfig secret not found, do nothing
		return nil
	case err != nil:
		return err
	}

	bootstrapKubeconfig, err := k.loadKubeConfig(bootstrapHubKubeconfigSecret)
	if err != nil {
		// a bad bootstrap secret, ignore it
		controllerContext.Recorder().Warningf("BadBootstrapSecret",
			fmt.Sprintf("unable to load hub kubeconfig from secret %s/%s: %v", agentNamespace, helpers.BootstrapHubKubeConfig, err))
		return nil
	}

	hubKubeconfigSecret, err := k.secretInformers[helpers.HubKubeConfig].Lister().Secrets(agentNamespace).Get(helpers.HubKubeConfig)
	switch {
	case errors.IsNotFound(err):
		// the hub kubeconfig secret not found, could not have bootstrap yet, do nothing currently
		// TODO one case should be supported in the future: the bootstrap phase may be failed due to
		// the content of bootstrap secret is wrong, this also results in the hub kubeconfig secret
		// cannot be found. In this case, user may need to correct the bootstrap secret. we need to
		// find a way to know the bootstrap secret is corrected, and then reload the klusterlet
		return nil
	case err != nil:
		return err
	}

	hubKubeconfig, err := k.loadKubeConfig(hubKubeconfigSecret)
	if err != nil {
		// the hub kubeconfig secret has errors, do nothing
		controllerContext.Recorder().Warningf("BadHubKubeConfigSecret",
			fmt.Sprintf("unable to load hub kubeconfig from secret %s/%s: %v", agentNamespace, helpers.BootstrapHubKubeConfig, err))
		return nil
	}

	if bootstrapKubeconfig.Server != hubKubeconfig.Server ||
		!bytes.Equal(bootstrapKubeconfig.CertificateAuthorityData, hubKubeconfig.CertificateAuthorityData) {
		// the bootstrap kubeconfig secret is changed, reload the klusterlet agents
		reloadReason := fmt.Sprintf("the bootstrap secret %s/%s is changed", agentNamespace, helpers.BootstrapHubKubeConfig)
		return k.startRebootstrap(ctx, klusterletName, reloadReason, controllerContext.Recorder(), requeueFunc)
	}

	expired, err := isHubKubeconfigSecretExpired(hubKubeconfigSecret)
	if err != nil {
		// the hub kubeconfig secret has errors, do nothing
		controllerContext.Recorder().Warningf("BadHubKubeConfigSecret",
			fmt.Sprintf("the hub kubeconfig secret %s/%s is invalid: %v", agentNamespace, helpers.HubKubeConfig, err))
		return nil
	}

	// the hub kubeconfig secret cert is not expired, do nothing
	if !expired {
		return nil
	}

	// the hub kubeconfig secret cert is expired, reload klusterlet to restart bootstrap
	reloadReason := fmt.Sprintf("the hub kubeconfig secret %s/%s is expired", agentNamespace, helpers.HubKubeConfig)
	return k.startRebootstrap(ctx, klusterletName, reloadReason, controllerContext.Recorder(), requeueFunc)
}

func (k *bootstrapController) processRebootstrap(ctx context.Context, agentNamespace, klusterletName string, recorder events.Recorder, requeueFunc func(time.Duration)) error {
	deploymentName := fmt.Sprintf("%s-registration-agent", klusterletName)
	deployment, err := k.kubeClient.AppsV1().Deployments(agentNamespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return k.completeRebootstrap(ctx, agentNamespace, klusterletName, recorder)
	}
	if err != nil {
		return err
	}

	if deployment.Status.AvailableReplicas == 0 {
		return k.completeRebootstrap(ctx, agentNamespace, klusterletName, recorder)
	}

	// there still is registation agent pod running. Resync in 5 seconds
	requeueFunc(5 * time.Second)
	return nil
}

func (k *bootstrapController) startRebootstrap(ctx context.Context, klusterletName, message string, recorder events.Recorder, requeueFunc func(duration time.Duration)) error {
	condition := metav1.Condition{
		Type:    helpers.KlusterletRebootstrapProgressing,
		Status:  metav1.ConditionTrue,
		Reason:  "RebootstrapStarted",
		Message: message,
	}
	_, _, err := helpers.UpdateKlusterletStatus(ctx, k.klusterletClient, klusterletName,
		helpers.UpdateKlusterletConditionFn(condition),
	)
	if err != nil {
		return err
	}
	recorder.Eventf("KlusterletRebootstrap", fmt.Sprintf("The klusterlet %q starts rebootstrapping due to %s",
		klusterletName, message))

	// requeue and check the rebootstrap progress in 5 seconds
	requeueFunc(5 * time.Second)
	return nil
}

func (k *bootstrapController) completeRebootstrap(ctx context.Context, agentNamespace, klusterletName string, recorder events.Recorder) error {
	// delete the existing hub kubeconfig
	if err := k.kubeClient.CoreV1().Secrets(agentNamespace).Delete(ctx, helpers.HubKubeConfig, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		return err
	}
	recorder.Eventf("KlusterletRebootstrap", fmt.Sprintf("Secret %s/%s is deleted", agentNamespace, helpers.HubKubeConfig))

	// update the condition of klusterlet
	condition := metav1.Condition{
		Type:    helpers.KlusterletRebootstrapProgressing,
		Status:  metav1.ConditionFalse,
		Reason:  "RebootstrapCompleted",
		Message: fmt.Sprintf("Secret %s/%s is deleted and bootstrap is triggered", agentNamespace, helpers.HubKubeConfig),
	}
	_, _, err := helpers.UpdateKlusterletStatus(ctx, k.klusterletClient, klusterletName,
		helpers.UpdateKlusterletConditionFn(condition),
	)
	if err != nil {
		return err
	}
	recorder.Eventf("KlusterletRebootstrap", fmt.Sprintf("Rebootstrap of the klusterlet %q is completed", klusterletName))
	return nil
}

func (k *bootstrapController) loadKubeConfig(secret *corev1.Secret) (*clientcmdapi.Cluster, error) {
	kubeconfig, ok := secret.Data["kubeconfig"]
	if !ok {
		return nil, fmt.Errorf("unable to get kubeconfig in secret")
	}
	config, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return nil, err
	}
	currentContext, ok := config.Contexts[config.CurrentContext]
	if !ok {
		return nil, fmt.Errorf("unable to get current-context in kubeconfig")
	}
	cluster, ok := config.Clusters[currentContext.Cluster]
	if !ok {
		return nil, fmt.Errorf("unable to get current cluster %q in kubeconfig", currentContext.Cluster)
	}
	return cluster, nil
}

func bootstrapSecretQueueKeyFunc(klusterletLister operatorlister.KlusterletLister) factory.ObjectQueueKeyFunc {
	return func(obj runtime.Object) string {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return ""
		}
		name := accessor.GetName()
		if name != helpers.BootstrapHubKubeConfig {
			return ""
		}

		namespace := accessor.GetNamespace()
		klusterlets, err := klusterletLister.List(labels.Everything())
		if err != nil {
			return ""
		}

		if klusterlet := helpers.FindKlusterletByNamespace(klusterlets, namespace); klusterlet != nil {
			return namespace + "/" + klusterlet.Name
		}

		return ""
	}
}

func isHubKubeconfigSecretExpired(secret *corev1.Secret) (bool, error) {
	certData, ok := secret.Data[tlsCertFile]
	if !ok {
		return false, fmt.Errorf("there is no %q", tlsCertFile)
	}

	certs, err := certutil.ParseCertsPEM(certData)
	if err != nil {
		return false, fmt.Errorf("failed to parse cert: %v", err)
	}

	if len(certs) == 0 {
		return false, fmt.Errorf("there are no certs in %q", tlsCertFile)
	}

	now := time.Now()
	for _, cert := range certs {
		if now.After(cert.NotAfter) {
			return true, nil
		}
	}

	return false, nil
}
