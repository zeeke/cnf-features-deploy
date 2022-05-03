package multinetworkpolicy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"

	multinetpolicyv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	sriovClean "github.com/k8snetworkplumbingwg/sriov-network-operator/test/util/clean"
	sriovtestclient "github.com/k8snetworkplumbingwg/sriov-network-operator/test/util/client"
	sriovcluster "github.com/k8snetworkplumbingwg/sriov-network-operator/test/util/cluster"
	sriovNamespaces "github.com/k8snetworkplumbingwg/sriov-network-operator/test/util/namespaces"
	"github.com/k8snetworkplumbingwg/sriov-network-operator/test/util/network"
	sriovNetwork "github.com/k8snetworkplumbingwg/sriov-network-operator/test/util/network"
	client "github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/client"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/discovery"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/namespaces"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/nodes"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/pods"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/sriov"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	resourceName = "sriovnicMultiNetworkpolicyResource"
	testNetwork  = "test-multi-networkpolicy-sriov-network"
)

var _ = Describe("[multinetworkpolicy] [sriov] integration", func() {

	sriovclient := sriovtestclient.New("")
	var nodesList []string

	BeforeEach(func() {

		if discovery.Enabled() {
			Skip("Discovery is not supported.")
		}

		err := namespaces.CleanPods(sriovNamespaces.Test, client.Client)
		Expect(err).ToNot(HaveOccurred())

		err = sriovClean.All()
		Expect(err).ToNot(HaveOccurred())
		sriov.WaitStable(sriovclient)

		err = namespaces.Create(sriovNamespaces.Test, client.Client)
		Expect(err).ToNot(HaveOccurred())

		sriovInfos, err := sriovcluster.DiscoverSriov(sriovclient, namespaces.SRIOVOperator)
		Expect(err).ToNot(HaveOccurred())
		Expect(sriovInfos).ToNot(BeNil())
		nodesList, err = nodes.MatchingOptionalSelectorByName(sriovInfos.Nodes)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodesList)).To(BeNumerically(">", 0))
		sriovDevice, err := sriovInfos.FindOneSriovDevice(nodesList[0])
		Expect(err).ToNot(HaveOccurred())

		_, err = sriovNetwork.CreateSriovPolicy(sriovclient, "test-policy-", namespaces.SRIOVOperator,
			sriovDevice.Name, nodesList[0], 5, resourceName, "netdevice")
		Expect(err).ToNot(HaveOccurred())

		sriov.WaitStable(sriovclient)

		ipam := `{
      		"type": "host-local",
      		"subnet": "2.2.2.0/24",
      		"rangeStart": "2.2.2.8",
      		"rangeEnd": "2.2.2.67",
      		"routes": [{
        		"dst": "0.0.0.0/0"
      		}]
    	}`
		err = sriovNetwork.CreateSriovNetwork(sriovclient, sriovDevice, testNetwork, sriovNamespaces.Test,
			namespaces.SRIOVOperator, resourceName, ipam)
		Expect(err).ToNot(HaveOccurred())

		networkAttachDef := netattdefv1.NetworkAttachmentDefinition{}
		waitForObject(
			sriovclient,
			runtimeclient.ObjectKey{Name: testNetwork, Namespace: sriovNamespaces.Test},
			&networkAttachDef)

	})

	AfterEach(func() {
		// TODO clean up

		// fmt.Println("Press the Enter Key to continue")
		// fmt.Scanln()
	})

	Context("", func() {
		It("DENY all traffic to an application", func() {

			podA := pods.DefinePod(sriovNamespaces.Test)
			pods.RedefineWithLabel(podA, "app", "A")
			pods.RedefinePodWithNetwork(podA, testNetwork)
			redefineWithNetcatServer(podA)
			podA = createAndStartPod(podA)

			podB := pods.DefinePod(sriovNamespaces.Test)
			pods.RedefinePodWithNetwork(podB, testNetwork)
			redefineWithNetcatServer(podB)
			podB = createAndStartPod(podB)

			Eventually(podB, "30s", "1s").Should(BeAbleToSendTrafficTo(podA))

			multiNetPolicy := defineMultiNetworkPolicy(sriovclient, testNetwork)
			multiNetPolicy.Spec = multinetpolicyv1.MultiNetworkPolicySpec{
				PolicyTypes: []multinetpolicyv1.MultiPolicyType{
					multinetpolicyv1.PolicyTypeIngress,
				},
				Ingress: []multinetpolicyv1.MultiNetworkPolicyIngressRule{},
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "A",
					},
				},
			}

			_, err := client.Client.MultiNetworkPolicies(sriovNamespaces.Test).
				Create(context.Background(), multiNetPolicy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			Eventually(podB, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(podA))
		})
	})
})

func waitForObject(clientSet *sriovtestclient.ClientSet, key runtimeclient.ObjectKey, object runtimeclient.Object) {

	Eventually(func() error {
		return clientSet.Get(context.Background(), key, object)
	}, 120*time.Second, 1*time.Second).
		WithOffset(1).
		ShouldNot(
			HaveOccurred(),
			"Object [%s] not found for key [%s]", reflect.TypeOf(object), key,
		)
}

func defineMultiNetworkPolicy(clientSet *sriovtestclient.ClientSet, targetNetwork string) *multinetpolicyv1.MultiNetworkPolicy {
	ret := multinetpolicyv1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-multinetwork-policy-",
			Namespace:    sriovNamespaces.Test,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": targetNetwork,
			},
		},
	}

	return &ret
}

func redefineWithNetcatServer(pod *corev1.Pod) *corev1.Pod {
	pod.Spec.Containers[0].Command = []string{"bash", "-c", "while true; do nc -l 0.0.0.0 5555; done"}
	return pod
}

func createAndStartPod(pod *corev1.Pod) *corev1.Pod {
	res, err := client.Client.Pods(pod.Namespace).
		Create(context.Background(), pod, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())

	Eventually(func() (corev1.PodPhase, error) {
		res, err = client.Client.Pods(res.Namespace).Get(context.Background(), res.Name, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred(), "Error while creating")
		return res.Status.Phase, err
	}, 1*time.Minute, 10*time.Second).Should(Equal(corev1.PodRunning))

	return res
}

type TrafficMatcherFactory struct {
	sriovclient *sriovtestclient.ClientSet
}

func (t *TrafficMatcherFactory) SendTrafficTo(destinationPod *corev1.Pod) types.GomegaMatcher {
	return &SendTrafficToMatcher{
		destinationPod: destinationPod,
		sriovclient:    t.sriovclient,
	}
}

func BeAbleToSendTrafficTo(destinationPod *corev1.Pod) types.GomegaMatcher {
	return &SendTrafficToMatcher{
		destinationPod: destinationPod,
		sriovclient:    nil,
	}
}

type SendTrafficToMatcher struct {
	destinationPod *corev1.Pod
	sriovclient    *sriovtestclient.ClientSet
}

func (m *SendTrafficToMatcher) Match(actual interface{}) (bool, error) {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return false, fmt.Errorf("SendTrafficToMatcher must be passed an *Pod. Got\n%s", format.Object(actual, 1))
	}

	destinationIps, err := network.GetSriovNicIPs(m.destinationPod, "net1")
	if err != nil {
		return false, fmt.Errorf("can't determine destination pod [%s] SR-IOV ip address: %w ", m.destinationPod.Name, err)
	}

	if len(destinationIps) == 0 {
		return false, fmt.Errorf("no ip address found for destination pod [%s] SR-IOV ip address: %w ", m.destinationPod.Name, err)
	}

	output, err := pods.ExecCommand(client.Client, *sourcePod, []string{"bash", "-c", fmt.Sprintf("echo xxx | nc -w 3 %s 5555", destinationIps[0])})
	if err != nil {
		if strings.Contains(output.String(), "Ncat: Connection timed out") {
			// Return err == nil to allow assertion on connectivity absence
			return false, nil
		}
		return false, fmt.Errorf("can't connect pods [%s] -> [%s]: %w ", sourcePod.Name, m.destinationPod.Name, err)
	}

	return true, nil
}

func (matcher *SendTrafficToMatcher) FailureMessage(actual interface{}) string {
	// TODO
	return fmt.Sprintf("TODO")
}

func (matcher *SendTrafficToMatcher) NegatedFailureMessage(actual interface{}) string {
	// TODO
	return fmt.Sprintf("TODO")
}
