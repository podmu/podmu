package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

var strictlyIgnoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey   = "podmu/inject"
	admissionWebhookAnnotationStatusKey   = "podmu/status"
	admissionWebhookAnnotationOverrideKey = "podmu/override"
	admissionWebhookAnnotationErrorKey    = "podmu/error"
)

type WebhookServer struct {
	server *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	insecureSkipVerify bool   // skip verifying client Certificates
	port               int    // webhook server port
	certFile           string // path to the x509 certificate for https
	keyFile            string // path to the x509 private key matching `CertFile`
	cfgDir             string // path to configuration dir
}

type Config struct {
	InitContainers  []corev1.Container         `yaml:"initContainers,omitempty"`
	Containers      []corev1.Container         `yaml:"containers,omitempty"`
	Volumes         []corev1.Volume            `yaml:"volumes,omitempty"`
	SecurityContext *corev1.PodSecurityContext `yaml:"securityContext,omitempty"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = corev1.AddToScheme(runtimeScheme)
}

// (https://github.com/kubernetes/kubernetes/issues/57982)
func applyDefaultsWorkaround(containers []corev1.Container, volumes []corev1.Volume) {
	defaulter.Default(&corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: containers,
			Volumes:    volumes,
		},
	})
}

func loadConfig(configFile string, configContentOverride string) (*Config, error) {
	var data []byte
	if configContentOverride != "" {
		data = ([]byte)(configContentOverride)
	}
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) (required bool, cfgFileName, cfgContent string) {
	required = false

	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %v for it's in special namespace:%v", metadata.Name, metadata.Namespace)
			return
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	if strings.ToLower(status) != "injected" {
		cfgFileName = annotations[admissionWebhookAnnotationInjectKey]
		cfgContent = annotations[admissionWebhookAnnotationOverrideKey]
		if cfgFileName != "" || cfgContent != "" {
			required = true
		}
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required: %v cfgFileName: %v", metadata.Namespace, metadata.Name, status, required, cfgFileName)
	return
}

func editPodSecurityContext(target, edit *corev1.PodSecurityContext, basePath string) (patch []patchOperation) {
	if edit == nil {
		return nil
	}
	if edit.RunAsUser != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "runAsUser"),
			Value: *edit.RunAsUser,
		})
	}
	if edit.RunAsGroup != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "runAsGroup"),
			Value: *edit.RunAsGroup,
		})
	}
	if edit.RunAsNonRoot != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "runAsNonRoot"),
			Value: *edit.RunAsNonRoot,
		})
	}
SUPPLE_EDIT_LOOP:
	for _, groupID := range edit.SupplementalGroups {
		for _, targetGroupID := range target.SupplementalGroups {
			if targetGroupID == groupID { // this group existed
				// -> skip
				continue SUPPLE_EDIT_LOOP
			}
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  fmt.Sprintf("%s/%s/-", basePath, "supplementalGroups"),
			Value: groupID,
		})
	}
	if edit.FSGroup != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "fsGroup"),
			Value: *edit.FSGroup,
		})
	}
	if edit.FSGroupChangePolicy != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "fsGroupChangePolicy"),
			Value: *edit.FSGroupChangePolicy,
		})
	}
	if len(edit.Sysctls) != 0 {
		sysctlsPath := fmt.Sprintf("%s/%s", basePath, "sysctls")
		if len(target.Sysctls) == 0 {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  sysctlsPath,
				Value: edit.Sysctls,
			})
		} else { // len(target.Sysctls) != 0
		SYSCTL_EDIT_LOOP:
			for _, editSysctl := range edit.Sysctls {
				for idx, targetSysctl := range target.Sysctls {
					if targetSysctl.Name != editSysctl.Name {
						continue
					}
					patch = append(patch, patchOperation{
						Op:    "replace",
						Path:  fmt.Sprintf("%s/%d/value", sysctlsPath, idx),
						Value: editSysctl.Value,
					})
					continue SYSCTL_EDIT_LOOP
				}
				patch = append(patch, patchOperation{
					Op:    "add",
					Path:  fmt.Sprintf("%s/-", sysctlsPath),
					Value: editSysctl,
				})
			}
		}
	}
	return patch
}

func editSecurityContext(edit *corev1.SecurityContext, basePath string) (patch []patchOperation) {
	if edit == nil {
		return nil
	}
	if edit.Privileged != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "privileged"),
			Value: *edit.Privileged,
		})
	}
	if edit.RunAsUser != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "runAsUser"),
			Value: *edit.RunAsUser,
		})
	}
	if edit.RunAsGroup != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "runAsGroup"),
			Value: *edit.RunAsGroup,
		})
	}
	if edit.RunAsNonRoot != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "runAsNonRoot"),
			Value: *edit.RunAsNonRoot,
		})
	}
	if edit.ReadOnlyRootFilesystem != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "readOnlyRootFilesystem"),
			Value: *edit.ReadOnlyRootFilesystem,
		})
	}
	if edit.AllowPrivilegeEscalation != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "allowPrivilegeEscalation"),
			Value: *edit.AllowPrivilegeEscalation,
		})
	}
	if edit.ProcMount != nil {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("%s/%s", basePath, "procMount"),
			Value: *edit.ProcMount,
		})
	}
	return patch
}

func editContainerSecurityContext(targets, edits []corev1.Container, basePath string) (patch []patchOperation) {
	for idx, target := range targets {
		name := target.Name
		for _, edit := range edits {
			// container edits specified without a name or an empty name will override all other existing target containers
			if edit.Name != "" && edit.Name != name {
				continue
			}
			secCtxPath := fmt.Sprintf("%s/%d/securityContext", basePath, idx)
			patch = append(patch, editSecurityContext(edit.SecurityContext, secCtxPath)...)
		}
	}
	return patch
}

func editContainerResources(targets, edits []corev1.Container, basePath string) (patch []patchOperation) {
	var value interface{}
	for idx, target := range targets {
		name := target.Name
		for _, edit := range edits {
			// container edits specified without a name or an empty name will override all other existing target containers
			if edit.Name != "" && edit.Name != name {
				continue
			}
			resourcesPath := fmt.Sprintf("%s/%d/resources", basePath, idx)
			for key, val := range edit.Resources.Requests {
				path := fmt.Sprintf("%s/requests/%s", resourcesPath, key)
				value = val
				patch = append(patch, patchOperation{
					Op:    "replace",
					Path:  path,
					Value: value,
				})
			}
			for key, val := range edit.Resources.Limits {
				path := fmt.Sprintf("%s/limits/%s", resourcesPath, key)
				value = val
				patch = append(patch, patchOperation{
					Op:    "replace",
					Path:  path,
					Value: value,
				})
			}
		}

	}
	return patch
}

func addContainer(targets, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(targets) == 0
	var value interface{}
added_loop:
	for _, add := range added {
		if add.Image == "" {
			// only add if Image is defined, otherwise, treat it as modification to Resources field
			continue added_loop
		}

		for _, target := range targets {
			if add.Name == target.Name {
				// skipping due to naming conflict
				continue added_loop
			}
		}
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, cfg *Config, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation

	if cfg != nil {
		patch = append(patch, addContainer(pod.Spec.Containers, cfg.Containers, "/spec/containers")...)
		patch = append(patch, addContainer(pod.Spec.InitContainers, cfg.InitContainers, "/spec/initContainers")...)

		patch = append(patch, editContainerResources(pod.Spec.Containers, cfg.Containers, "/spec/containers")...)
		patch = append(patch, editContainerResources(pod.Spec.InitContainers, cfg.InitContainers, "/spec/initContainers")...)

		patch = append(patch, editContainerSecurityContext(pod.Spec.Containers, cfg.Containers, "/spec/containers")...)
		patch = append(patch, editContainerSecurityContext(pod.Spec.InitContainers, cfg.InitContainers, "/spec/initContainers")...)

		patch = append(patch, addVolume(pod.Spec.Volumes, cfg.Volumes, "/spec/volumes")...)
		patch = append(patch, editPodSecurityContext(pod.Spec.SecurityContext, cfg.SecurityContext, "/spec/securityContext")...)
	}

	if annotations != nil {
		patch = append(patch, updateAnnotation(pod.Annotations, annotations)...) // adding "podmu/status: injected"
	}

	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	var (
		required           bool
		cfgFileName        string
		cfgContentOverride string
	)
	// determine whether to perform mutation
	if required, cfgFileName, cfgContentOverride = mutationRequired(strictlyIgnoredNamespaces, &pod.ObjectMeta); !required {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	var (
		patchBytes []byte
		err        error
	)
	cfg, err := loadConfig(filepath.Join(parameters.cfgDir, cfgFileName), cfgContentOverride)
	if err != nil {
		glog.Errorf("Failed to load configuration `%s`: %v", cfgFileName, err)
		annotations := map[string]string{admissionWebhookAnnotationErrorKey: "loadConfig error: " + err.Error()}
		patchBytes, err = createPatch(&pod, nil, annotations)
		if err != nil {
			glog.Errorf("Mutation to add annotations error messages failed on %s:%s: %v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, err)
			return &v1beta1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	} else {
		// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
		applyDefaultsWorkaround(cfg.Containers, cfg.Volumes)
		annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
		patchBytes, err = createPatch(&pod, cfg, annotations)
		if err != nil {
			glog.Errorf("Mutation failed on %s:%s: %v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, err)
			return &v1beta1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func (whsvr *WebhookServer) healthz(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %+v", parameters)
}
