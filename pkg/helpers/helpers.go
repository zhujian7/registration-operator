package helpers

import (
	"context"
	"fmt"
	"reflect"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	admissionclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	operatorv1client "open-cluster-management.io/api/client/operator/clientset/versioned/typed/operator/v1"
	operatorapiv1 "open-cluster-management.io/api/operator/v1"

	"github.com/openshift/api"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

const (
	defaultReplica = 3
	singleReplica  = 1
)

var (
	genericScheme = runtime.NewScheme()
	genericCodecs = serializer.NewCodecFactory(genericScheme)
	genericCodec  = genericCodecs.UniversalDeserializer()
)

func init() {
	utilruntime.Must(api.InstallKube(genericScheme))
	utilruntime.Must(apiextensionsv1beta1.AddToScheme(genericScheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(genericScheme))
	utilruntime.Must(apiregistrationv1.AddToScheme(genericScheme))
	utilruntime.Must(admissionv1.AddToScheme(genericScheme))
}

type UpdateClusterManagerStatusFunc func(status *operatorapiv1.ClusterManagerStatus) error

func UpdateClusterManagerStatus(
	ctx context.Context,
	client operatorv1client.ClusterManagerInterface,
	clusterManagerName string,
	updateFuncs ...UpdateClusterManagerStatusFunc) (*operatorapiv1.ClusterManagerStatus, bool, error) {
	updated := false
	var updatedClusterManagerStatus *operatorapiv1.ClusterManagerStatus
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		clusterManager, err := client.Get(ctx, clusterManagerName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		oldStatus := &clusterManager.Status

		newStatus := oldStatus.DeepCopy()
		for _, update := range updateFuncs {
			if err := update(newStatus); err != nil {
				return err
			}
		}
		if equality.Semantic.DeepEqual(oldStatus, newStatus) {
			// We return the newStatus which is a deep copy of oldStatus but with all update funcs applied.
			updatedClusterManagerStatus = newStatus
			return nil
		}

		clusterManager.Status = *newStatus
		updatedClusterManager, err := client.UpdateStatus(ctx, clusterManager, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		updatedClusterManagerStatus = &updatedClusterManager.Status
		updated = err == nil
		return err
	})

	return updatedClusterManagerStatus, updated, err
}

func UpdateClusterManagerConditionFn(conds ...metav1.Condition) UpdateClusterManagerStatusFunc {
	return func(oldStatus *operatorapiv1.ClusterManagerStatus) error {
		for _, cond := range conds {
			meta.SetStatusCondition(&oldStatus.Conditions, cond)
		}
		return nil
	}
}

type UpdateKlusterletStatusFunc func(status *operatorapiv1.KlusterletStatus) error

func UpdateKlusterletStatus(
	ctx context.Context,
	client operatorv1client.KlusterletInterface,
	klusterletName string,
	updateFuncs ...UpdateKlusterletStatusFunc) (*operatorapiv1.KlusterletStatus, bool, error) {
	updated := false
	var updatedKlusterletStatus *operatorapiv1.KlusterletStatus
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		klusterlet, err := client.Get(ctx, klusterletName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		oldStatus := &klusterlet.Status

		newStatus := oldStatus.DeepCopy()
		for _, update := range updateFuncs {
			if err := update(newStatus); err != nil {
				return err
			}
		}
		if equality.Semantic.DeepEqual(oldStatus, newStatus) {
			// We return the newStatus which is a deep copy of oldStatus but with all update funcs applied.
			updatedKlusterletStatus = newStatus
			return nil
		}

		klusterlet.Status = *newStatus
		updatedKlusterlet, err := client.UpdateStatus(ctx, klusterlet, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		updatedKlusterletStatus = &updatedKlusterlet.Status
		updated = err == nil
		return err
	})

	return updatedKlusterletStatus, updated, err
}

func UpdateKlusterletConditionFn(conds ...metav1.Condition) UpdateKlusterletStatusFunc {
	return func(oldStatus *operatorapiv1.KlusterletStatus) error {
		for _, cond := range conds {
			meta.SetStatusCondition(&oldStatus.Conditions, cond)
		}
		return nil
	}
}

func CleanUpStaticObject(
	ctx context.Context,
	client kubernetes.Interface,
	apiExtensionClient apiextensionsclient.Interface,
	apiRegistrationClient apiregistrationclient.APIServicesGetter,
	manifests resourceapply.AssetFunc,
	file string) error {
	objectRaw, err := manifests(file)
	if err != nil {
		return err
	}
	object, _, err := genericCodec.Decode(objectRaw, nil, nil)
	if err != nil {
		return err
	}
	switch t := object.(type) {
	case *corev1.Namespace:
		err = client.CoreV1().Namespaces().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *corev1.Service:
		err = client.CoreV1().Services(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *corev1.ServiceAccount:
		err = client.CoreV1().ServiceAccounts(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *corev1.ConfigMap:
		err = client.CoreV1().ConfigMaps(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *corev1.Secret:
		err = client.CoreV1().Secrets(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *rbacv1.ClusterRole:
		err = client.RbacV1().ClusterRoles().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *rbacv1.ClusterRoleBinding:
		err = client.RbacV1().ClusterRoleBindings().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *rbacv1.Role:
		err = client.RbacV1().Roles(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *rbacv1.RoleBinding:
		err = client.RbacV1().RoleBindings(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *apiextensionsv1.CustomResourceDefinition:
		err = apiExtensionClient.ApiextensionsV1().CustomResourceDefinitions().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *apiextensionsv1beta1.CustomResourceDefinition:
		err = apiExtensionClient.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *apiregistrationv1.APIService:
		err = apiRegistrationClient.APIServices().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *admissionv1.ValidatingWebhookConfiguration:
		err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, t.Name, metav1.DeleteOptions{})
	case *admissionv1.MutatingWebhookConfiguration:
		err = client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, t.Name, metav1.DeleteOptions{})
	default:
		err = fmt.Errorf("unhandled type %T", object)
	}
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

func ApplyValidatingWebhookConfiguration(
	client admissionclient.ValidatingWebhookConfigurationsGetter,
	required *admissionv1.ValidatingWebhookConfiguration) (*admissionv1.ValidatingWebhookConfiguration, bool, error) {
	existing, err := client.ValidatingWebhookConfigurations().Get(context.TODO(), required.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		actual, err := client.ValidatingWebhookConfigurations().Create(context.TODO(), required, metav1.CreateOptions{})
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	if !equality.Semantic.DeepEqual(existingCopy.Webhooks, required.Webhooks) {
		*modified = true
		existing.Webhooks = required.Webhooks
	}
	if !*modified {
		return existing, false, nil
	}

	actual, err := client.ValidatingWebhookConfigurations().Update(context.TODO(), existingCopy, metav1.UpdateOptions{})
	return actual, true, err
}

func ApplyMutatingWebhookConfiguration(
	client admissionclient.MutatingWebhookConfigurationsGetter,
	required *admissionv1.MutatingWebhookConfiguration) (*admissionv1.MutatingWebhookConfiguration, bool, error) {
	existing, err := client.MutatingWebhookConfigurations().Get(context.TODO(), required.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		actual, err := client.MutatingWebhookConfigurations().Create(context.TODO(), required, metav1.CreateOptions{})
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	if !equality.Semantic.DeepEqual(existingCopy.Webhooks, required.Webhooks) {
		*modified = true
		existing.Webhooks = required.Webhooks
	}
	if !*modified {
		return existing, false, nil
	}

	actual, err := client.MutatingWebhookConfigurations().Update(context.TODO(), existingCopy, metav1.UpdateOptions{})
	return actual, true, err
}

func ApplyDeployment(
	client kubernetes.Interface,
	generationStatuses []operatorapiv1.GenerationStatus,
	nodePlacement operatorapiv1.NodePlacement,
	manifests resourceapply.AssetFunc,
	recorder events.Recorder, file string) (operatorapiv1.GenerationStatus, error) {
	deploymentBytes, err := manifests(file)
	if err != nil {
		return operatorapiv1.GenerationStatus{}, err
	}
	deployment, _, err := genericCodec.Decode(deploymentBytes, nil, nil)
	if err != nil {
		return operatorapiv1.GenerationStatus{}, fmt.Errorf("%q: %v", file, err)
	}
	generationStatus := NewGenerationStatus(appsv1.SchemeGroupVersion.WithResource("deployments"), deployment)
	currentGenerationStatus := FindGenerationStatus(generationStatuses, generationStatus)

	if currentGenerationStatus != nil {
		generationStatus.LastGeneration = currentGenerationStatus.LastGeneration
	}

	deployment.(*appsv1.Deployment).Spec.Template.Spec.NodeSelector = nodePlacement.NodeSelector
	deployment.(*appsv1.Deployment).Spec.Template.Spec.Tolerations = nodePlacement.Tolerations

	updatedDeployment, updated, err := resourceapply.ApplyDeployment(
		client.AppsV1(),
		recorder,
		deployment.(*appsv1.Deployment), generationStatus.LastGeneration)
	if err != nil {
		return generationStatus, fmt.Errorf("%q (%T): %v", file, deployment, err)
	}

	if updated {
		generationStatus.LastGeneration = updatedDeployment.ObjectMeta.Generation
	}

	return generationStatus, nil
}

func ApplyDirectly(
	client kubernetes.Interface,
	apiExtensionClient apiextensionsclient.Interface,
	apiRegistrationClient apiregistrationclient.APIServicesGetter,
	recorder events.Recorder,
	manifests resourceapply.AssetFunc,
	files ...string) []resourceapply.ApplyResult {
	ret := []resourceapply.ApplyResult{}
	genericApplyFiles := []string{}
	for _, file := range files {
		result := resourceapply.ApplyResult{File: file}
		objBytes, err := manifests(file)
		if err != nil {
			result.Error = fmt.Errorf("missing %q: %v", file, err)
			ret = append(ret, result)
			continue
		}
		requiredObj, _, err := genericCodec.Decode(objBytes, nil, nil)
		if err != nil {
			result.Error = fmt.Errorf("cannot decode %q: %v", file, err)
			ret = append(ret, result)
			continue
		}
		result.Type = fmt.Sprintf("%T", requiredObj)
		switch t := requiredObj.(type) {
		case *admissionv1.ValidatingWebhookConfiguration:
			result.Result, result.Changed, result.Error = ApplyValidatingWebhookConfiguration(
				client.AdmissionregistrationV1(), t)
		case *admissionv1.MutatingWebhookConfiguration:
			result.Result, result.Changed, result.Error = ApplyMutatingWebhookConfiguration(
				client.AdmissionregistrationV1(), t)
		case *apiregistrationv1.APIService:
			result.Result, result.Changed, result.Error = resourceapply.ApplyAPIService(apiRegistrationClient, recorder, t)
		default:
			genericApplyFiles = append(genericApplyFiles, file)
		}
	}

	clientHolder := resourceapply.NewKubeClientHolder(client).WithAPIExtensionsClient(apiExtensionClient)
	applyResults := resourceapply.ApplyDirectly(
		clientHolder,
		recorder,
		manifests,
		genericApplyFiles...,
	)

	ret = append(ret, applyResults...)
	return ret
}

// NumOfUnavailablePod is to check if a deployment is in degraded state.
func NumOfUnavailablePod(deployment *appsv1.Deployment) int32 {
	desiredReplicas := int32(1)
	if deployment.Spec.Replicas != nil {
		desiredReplicas = *(deployment.Spec.Replicas)
	}

	if desiredReplicas <= deployment.Status.AvailableReplicas {
		return 0
	}

	return desiredReplicas - deployment.Status.AvailableReplicas
}

func NewGenerationStatus(gvr schema.GroupVersionResource, object runtime.Object) operatorapiv1.GenerationStatus {
	accessor, _ := meta.Accessor(object)
	return operatorapiv1.GenerationStatus{
		Group:          gvr.Group,
		Version:        gvr.Version,
		Resource:       gvr.Resource,
		Namespace:      accessor.GetNamespace(),
		Name:           accessor.GetName(),
		LastGeneration: accessor.GetGeneration(),
	}
}

func FindGenerationStatus(generationStatuses []operatorapiv1.GenerationStatus, generation operatorapiv1.GenerationStatus) *operatorapiv1.GenerationStatus {
	for i := range generationStatuses {
		if generationStatuses[i].Group != generation.Group {
			continue
		}
		if generationStatuses[i].Resource != generation.Resource {
			continue
		}
		if generationStatuses[i].Version != generation.Version {
			continue
		}
		if generationStatuses[i].Name != generation.Name {
			continue
		}
		if generationStatuses[i].Namespace != generation.Namespace {
			continue
		}
		return &generationStatuses[i]
	}
	return nil
}

func SetGenerationStatuses(generationStatuses *[]operatorapiv1.GenerationStatus, newGenerationStatus operatorapiv1.GenerationStatus) {
	if generationStatuses == nil {
		generationStatuses = &[]operatorapiv1.GenerationStatus{}
	}

	existingGeneration := FindGenerationStatus(*generationStatuses, newGenerationStatus)
	if existingGeneration == nil {
		*generationStatuses = append(*generationStatuses, newGenerationStatus)
		return
	}

	existingGeneration.LastGeneration = newGenerationStatus.LastGeneration
}

func UpdateClusterManagerGenerationsFn(generations ...operatorapiv1.GenerationStatus) UpdateClusterManagerStatusFunc {
	return func(oldStatus *operatorapiv1.ClusterManagerStatus) error {
		for _, generation := range generations {
			SetGenerationStatuses(&oldStatus.Generations, generation)
		}
		return nil
	}
}

func UpdateKlusterletGenerationsFn(generations ...operatorapiv1.GenerationStatus) UpdateKlusterletStatusFunc {
	return func(oldStatus *operatorapiv1.KlusterletStatus) error {
		for _, generation := range generations {
			SetGenerationStatuses(&oldStatus.Generations, generation)
		}
		return nil
	}
}

// LoadClientConfigFromSecret returns a client config loaded from the given secret
func LoadClientConfigFromSecret(secret *corev1.Secret) (*restclient.Config, error) {
	kubeconfigData, ok := secret.Data["kubeconfig"]
	if !ok {
		return nil, fmt.Errorf("unable to find kubeconfig in secret %q %q",
			secret.Namespace, secret.Name)
	}

	config, err := clientcmd.Load(kubeconfigData)
	if err != nil {
		return nil, err
	}

	context, ok := config.Contexts[config.CurrentContext]
	if !ok {
		return nil, fmt.Errorf("unable to find the current context %q from the kubeconfig in secret %q %q",
			config.CurrentContext, secret.Namespace, secret.Name)
	}

	if authInfo, ok := config.AuthInfos[context.AuthInfo]; ok {
		// use embeded cert/key data instead of references to external cert/key files
		if certData, ok := secret.Data["tls.crt"]; ok && len(authInfo.ClientCertificateData) == 0 {
			authInfo.ClientCertificateData = certData
			authInfo.ClientCertificate = ""
		}
		if keyData, ok := secret.Data["tls.key"]; ok && len(authInfo.ClientKeyData) == 0 {
			authInfo.ClientKeyData = keyData
			authInfo.ClientKey = ""
		}
	}

	return clientcmd.NewDefaultClientConfig(*config, nil).ClientConfig()
}

// DetermineReplicaByNodes determines the replica of deployment based on:
// list master nodes in the cluster and return 1 if
// the number of master nodes is equal or less than 1. Return 3 otherwise.
func DetermineReplicaByNodes(ctx context.Context, kubeClient kubernetes.Interface) int32 {
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/master="})
	if err != nil {
		return defaultReplica
	}

	if len(nodes.Items) <= 1 {
		return singleReplica
	}

	return defaultReplica
}

func GenerateRelatedResource(objBytes []byte) (operatorapiv1.RelatedResourceMeta, error) {
	var relatedResource operatorapiv1.RelatedResourceMeta
	requiredObj, _, err := genericCodec.Decode(objBytes, nil, nil)
	if err != nil {
		return relatedResource, err
	}

	switch requiredObj.(type) {
	case *admissionv1.ValidatingWebhookConfiguration:
		relatedResource = newRelatedResource(admissionv1.SchemeGroupVersion.WithResource("validatingwebhookconfigurations"), requiredObj)
	case *admissionv1.MutatingWebhookConfiguration:
		relatedResource = newRelatedResource(admissionv1.SchemeGroupVersion.WithResource("mutatingwebhookconfigurations"), requiredObj)
	case *apiregistrationv1.APIService:
		relatedResource = newRelatedResource(apiregistrationv1.SchemeGroupVersion.WithResource("apiservices"), requiredObj)
	case *appsv1.Deployment:
		relatedResource = newRelatedResource(appsv1.SchemeGroupVersion.WithResource("deployments"), requiredObj)
	case *corev1.Namespace:
		relatedResource = newRelatedResource(corev1.SchemeGroupVersion.WithResource("namespaces"), requiredObj)
	case *corev1.Service:
		relatedResource = newRelatedResource(corev1.SchemeGroupVersion.WithResource("services"), requiredObj)
	case *corev1.Pod:
		relatedResource = newRelatedResource(corev1.SchemeGroupVersion.WithResource("pods"), requiredObj)
	case *corev1.ServiceAccount:
		relatedResource = newRelatedResource(corev1.SchemeGroupVersion.WithResource("serviceaccounts"), requiredObj)
	case *corev1.ConfigMap:
		relatedResource = newRelatedResource(corev1.SchemeGroupVersion.WithResource("configmaps"), requiredObj)
	case *corev1.Secret:
		relatedResource = newRelatedResource(corev1.SchemeGroupVersion.WithResource("secrets"), requiredObj)
	case *rbacv1.ClusterRole:
		relatedResource = newRelatedResource(rbacv1.SchemeGroupVersion.WithResource("clusterroles"), requiredObj)
	case *rbacv1.ClusterRoleBinding:
		relatedResource = newRelatedResource(rbacv1.SchemeGroupVersion.WithResource("clusterrolebindings"), requiredObj)
	case *rbacv1.Role:
		relatedResource = newRelatedResource(rbacv1.SchemeGroupVersion.WithResource("roles"), requiredObj)
	case *rbacv1.RoleBinding:
		relatedResource = newRelatedResource(rbacv1.SchemeGroupVersion.WithResource("rolebindings"), requiredObj)
	case *apiextensionsv1beta1.CustomResourceDefinition:
		relatedResource = newRelatedResource(apiextensionsv1beta1.SchemeGroupVersion.WithResource("customresourcedefinitions"), requiredObj)
	case *apiextensionsv1.CustomResourceDefinition:
		relatedResource = newRelatedResource(apiextensionsv1.SchemeGroupVersion.WithResource("customresourcedefinitions"), requiredObj)
	default:
		return relatedResource, fmt.Errorf("unhandled type %T", requiredObj)
	}

	return relatedResource, nil
}

func newRelatedResource(gvr schema.GroupVersionResource, obj runtime.Object) operatorapiv1.RelatedResourceMeta {
	accessor, _ := meta.Accessor(obj)
	return operatorapiv1.RelatedResourceMeta{
		Group:     gvr.Group,
		Version:   gvr.Version,
		Resource:  gvr.Resource,
		Namespace: accessor.GetNamespace(),
		Name:      accessor.GetName(),
	}
}

func SetRelatedResourcesStatuses(
	relatedResourcesStatuses *[]operatorapiv1.RelatedResourceMeta,
	newRelatedResourcesStatus operatorapiv1.RelatedResourceMeta) {
	if relatedResourcesStatuses == nil {
		relatedResourcesStatuses = &[]operatorapiv1.RelatedResourceMeta{}
	}

	existingRelatedResource := FindRelatedResourcesStatus(*relatedResourcesStatuses, newRelatedResourcesStatus)
	if existingRelatedResource == nil {
		*relatedResourcesStatuses = append(*relatedResourcesStatuses, newRelatedResourcesStatus)
		return
	}
}

func FindRelatedResourcesStatus(
	relatedResourcesStatuses []operatorapiv1.RelatedResourceMeta,
	relatedResource operatorapiv1.RelatedResourceMeta) *operatorapiv1.RelatedResourceMeta {
	for i := range relatedResourcesStatuses {
		if reflect.DeepEqual(relatedResourcesStatuses[i], relatedResource) {
			return &relatedResourcesStatuses[i]
		}
	}
	return nil
}

func SetRelatedResourcesStatusesWithObj(
	relatedResourcesStatuses *[]operatorapiv1.RelatedResourceMeta, objData []byte) {
	res, err := GenerateRelatedResource(objData)
	if err != nil {
		klog.Errorf("failed to generate relatedResource %v, and skip to set into status. %v", objData, err)
		return
	}
	SetRelatedResourcesStatuses(relatedResourcesStatuses, res)
	return
}

func UpdateClusterManagerRelatedResourcesFn(relatedResources ...operatorapiv1.RelatedResourceMeta) UpdateClusterManagerStatusFunc {
	return func(oldStatus *operatorapiv1.ClusterManagerStatus) error {
		if !reflect.DeepEqual(oldStatus.RelatedResources, relatedResources) {
			oldStatus.RelatedResources = relatedResources
		}
		return nil
	}
}

func UpdateKlusterletRelatedResourcesFn(relatedResources ...operatorapiv1.RelatedResourceMeta) UpdateKlusterletStatusFunc {
	return func(oldStatus *operatorapiv1.KlusterletStatus) error {
		if !reflect.DeepEqual(oldStatus.RelatedResources, relatedResources) {
			oldStatus.RelatedResources = relatedResources
		}
		return nil
	}
}

// KlusterletNamespace returns the klusterletNamespace to deploy the agents.
// Note in Detached mode, the specNamespace will be ignored.
func KlusterletNamespace(mode operatorapiv1.InstallMode, klusterletName, specNamespace string) string {
	if mode == operatorapiv1.InstallModeDetached {
		return klusterletName
	}

	if len(specNamespace) == 0 {
		// If namespace is not set, use the default namespace
		return KlusterletDefaultNamespace
	}

	return specNamespace
}

// SyncSecret forked from https://github.com/openshift/library-go/blob/d9cdfbd844ea08465b938c46a16bed2ea23207e4/pkg/operator/resource/resourceapply/core.go#L357,
// add an addition targetClient parameter to support sync secret to another cluster.
func SyncSecret(client, targetClient coreclientv1.SecretsGetter, recorder events.Recorder,
	sourceNamespace, sourceName, targetNamespace, targetName string, ownerRefs []metav1.OwnerReference) (*corev1.Secret, bool, error) {
	source, err := client.Secrets(sourceNamespace).Get(context.TODO(), sourceName, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		if _, getErr := targetClient.Secrets(targetNamespace).Get(context.TODO(), targetName, metav1.GetOptions{}); getErr != nil && errors.IsNotFound(getErr) {
			return nil, true, nil
		}
		deleteErr := targetClient.Secrets(targetNamespace).Delete(context.TODO(), targetName, metav1.DeleteOptions{})
		if errors.IsNotFound(deleteErr) {
			return nil, false, nil
		}
		if deleteErr == nil {
			recorder.Eventf("TargetSecretDeleted", "Deleted target secret %s/%s because source config does not exist", targetNamespace, targetName)
			return nil, true, nil
		}
		return nil, false, deleteErr
	case err != nil:
		return nil, false, err
	default:
		if source.Type == corev1.SecretTypeServiceAccountToken {

			// Make sure the token is already present, otherwise we have to wait before creating the target
			if len(source.Data[corev1.ServiceAccountTokenKey]) == 0 {
				return nil, false, fmt.Errorf("secret %s/%s doesn't have a token yet", source.Namespace, source.Name)
			}

			if source.Annotations != nil {
				// When syncing a service account token we have to remove the SA annotation to disable injection into copies
				delete(source.Annotations, corev1.ServiceAccountNameKey)
				// To make it clean, remove the dormant annotations as well
				delete(source.Annotations, corev1.ServiceAccountUIDKey)
			}

			// SecretTypeServiceAccountToken implies required fields and injection which we do not want in copies
			source.Type = corev1.SecretTypeOpaque
		}

		source.Namespace = targetNamespace
		source.Name = targetName
		source.ResourceVersion = ""
		source.OwnerReferences = ownerRefs
		return resourceapply.ApplySecret(targetClient, recorder, source)
	}
}
