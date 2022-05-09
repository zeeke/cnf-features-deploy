package multinetworkpolicy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
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
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/execute"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/images"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/namespaces"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/nodes"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/pods"
	"github.com/openshift-kni/cnf-features-deploy/cnf-tests/testsuites/pkg/sriov"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	resourceName          = "sriovnicMultiNetworkpolicyResource"
	testNetwork           = "test-multi-networkpolicy-sriov-network"
	testsNetworkNamespace = "default"
)

// Common test model
const nsX string = sriovNamespaces.Test + "-x"
const nsY string = sriovNamespaces.Test + "-y"
const nsZ string = sriovNamespaces.Test + "-z"

// TODO - remove this: https://github.com/kubernetes/kubernetes/blob/master/test/e2e/network/netpol/network_policy.go

var _ = Describe("[multinetworkpolicy] [sriov] integration", func() {

	sriovclient := sriovtestclient.New("")

	var nsX_podA, nsX_podB, nsX_podC *corev1.Pod
	var nsY_podA, nsY_podB, nsY_podC *corev1.Pod
	var nsZ_podA, nsZ_podB, nsZ_podC *corev1.Pod

	execute.BeforeAll(func() {

		if discovery.Enabled() {
			Skip("Discovery is not supported.")
		}

		cleanPodsInNamespaces(sriovNamespaces.Test, nsX, nsY, nsZ)

		Expect(sriovClean.All()).ToNot(HaveOccurred())
		sriov.WaitStable(sriovclient)

		createNamespaces(sriovNamespaces.Test, nsX, nsY, nsZ)

		sriovInfos, err := sriovcluster.DiscoverSriov(sriovclient, namespaces.SRIOVOperator)
		Expect(err).ToNot(HaveOccurred())
		Expect(sriovInfos).ToNot(BeNil())

		nodesList, err := nodes.MatchingOptionalSelectorByName(sriovInfos.Nodes)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodesList)).To(BeNumerically(">", 0))

		sriovDevice, err := sriovInfos.FindOneSriovDevice(nodesList[0])
		Expect(err).ToNot(HaveOccurred())

		_, err = sriovNetwork.CreateSriovPolicy(sriovclient, "test-policy-", namespaces.SRIOVOperator,
			sriovDevice.Name, nodesList[0], 10, resourceName, "netdevice")
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

		err = sriovNetwork.CreateSriovNetwork(sriovclient, sriovDevice, testNetwork, testsNetworkNamespace,
			namespaces.SRIOVOperator, resourceName, ipam)
		Expect(err).ToNot(HaveOccurred())

		networkAttachDef := netattdefv1.NetworkAttachmentDefinition{}
		waitForObject(
			sriovclient,
			runtimeclient.ObjectKey{Name: testNetwork, Namespace: testsNetworkNamespace},
			&networkAttachDef)

		nsX_podA, nsX_podB, nsX_podC = createPodsInNamespace(nsX)
		nsY_podA, nsY_podB, nsY_podC = createPodsInNamespace(nsY)
		nsZ_podA, nsZ_podB, nsZ_podC = createPodsInNamespace(nsZ)

		func(cc ...*corev1.Pod) {}(nsX_podC, nsY_podA, nsY_podB, nsY_podC, nsZ_podA, nsZ_podB, nsZ_podC)
	})

	BeforeEach(func() {
		cleanMultiNetworkPolicies(nsX)
		cleanMultiNetworkPolicies(nsY)
		cleanMultiNetworkPolicies(nsZ)
	})

	AfterEach(func() {
		// TODO clean up

		if CurrentGinkgoTestDescription().Failed {
			printConnectivityMatrix(
				nsX_podA, nsX_podB, nsX_podC,
				nsY_podA, nsY_podB, nsY_podC,
				nsZ_podA, nsZ_podB, nsZ_podC,
			)
		}

	})

	Context("", func() {
		It("DENY all traffic to a pod", func() {

			multiNetPolicy := defineMultiNetworkPolicy(testsNetworkNamespace + "/" + testNetwork)
			multiNetPolicy.Spec = multinetpolicyv1.MultiNetworkPolicySpec{
				PolicyTypes: []multinetpolicyv1.MultiPolicyType{
					multinetpolicyv1.PolicyTypeIngress,
				},
				Ingress: []multinetpolicyv1.MultiNetworkPolicyIngressRule{},
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				},
			}

			_, err := client.Client.MultiNetworkPolicies(nsX).
				Create(context.Background(), multiNetPolicy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Pod B and C are not affected by the policy
			Eventually(nsX_podB, "30s", "1s").Should(BeAbleToSendTrafficTo(nsX_podC))

			// Pod A should not be reacheable by B and C
			Eventually(nsX_podB, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podA))
			Eventually(nsX_podC, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podA))

			// nsX_podA should be able to send traffic to
			// Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podC))
		})

		It("DENY all traffic to/from/in a namespace", func() {

			multiNetPolicy := defineMultiNetworkPolicy(testsNetworkNamespace + "/" + testNetwork)
			multiNetPolicy.Spec = multinetpolicyv1.MultiNetworkPolicySpec{
				PolicyTypes: []multinetpolicyv1.MultiPolicyType{
					multinetpolicyv1.PolicyTypeIngress,
				},
				Ingress:     []multinetpolicyv1.MultiNetworkPolicyIngressRule{},
				Egress:      []multinetpolicyv1.MultiNetworkPolicyEgressRule{},
				PodSelector: metav1.LabelSelector{},
			}

			_, err := client.Client.MultiNetworkPolicies(nsX).
				Create(context.Background(), multiNetPolicy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Traffic within nsX is not allowed
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podB))
			Eventually(nsX_podB, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podC))
			Eventually(nsX_podC, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podA))

			// Traffic to/from nsX is not allowed
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsY_podA))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsZ_podA))

			// Traffic within other namespaces is allowed
			Eventually(nsY_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podB))
			Eventually(nsZ_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsZ_podB))

			// Traffic between other namespaces is allowed
			Eventually(nsY_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsZ_podA))
			Eventually(nsZ_podB, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podC))
		})

		It("ALLOW traffic to nsX_podA only from nsX_podB", func() {

			multiNetPolicy := defineMultiNetworkPolicy(testsNetworkNamespace + "/" + testNetwork)
			multiNetPolicy.Spec = multinetpolicyv1.MultiNetworkPolicySpec{
				PolicyTypes: []multinetpolicyv1.MultiPolicyType{
					multinetpolicyv1.PolicyTypeIngress,
				},
				Ingress: []multinetpolicyv1.MultiNetworkPolicyIngressRule{
					{
						From: []multinetpolicyv1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"pod": "b",
									},
								},
							},
						},
					},
				},
				Egress: []multinetpolicyv1.MultiNetworkPolicyEgressRule{},
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				},
			}

			_, err := client.Client.MultiNetworkPolicies(nsX).
				Create(context.Background(), multiNetPolicy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			// The subject of test case
			Eventually(nsX_podB, "30s", "1s").Should(BeAbleToSendTrafficTo(nsX_podA))
			Eventually(nsX_podC, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podA))

			// Traffic that should not be affected
			Eventually(nsX_podB, "30s", "1s").Should(BeAbleToSendTrafficTo(nsX_podC))
		})

		It("ALLOW traffic to nsX_podA only from (nsY/* OR nsZ/podB)", func() {
			multiNetPolicy := defineMultiNetworkPolicy(testsNetworkNamespace + "/" + testNetwork)
			multiNetPolicy.Spec = multinetpolicyv1.MultiNetworkPolicySpec{
				PolicyTypes: []multinetpolicyv1.MultiPolicyType{
					multinetpolicyv1.PolicyTypeIngress,
				},
				Ingress: []multinetpolicyv1.MultiNetworkPolicyIngressRule{
					{
						From: []multinetpolicyv1.MultiNetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"kubernetes.io/metadata.name": nsY,
									},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"pod": "b",
									},
								},
							},
						},
					},
				},
				Egress: []multinetpolicyv1.MultiNetworkPolicyEgressRule{},
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				},
			}

			_, err := client.Client.MultiNetworkPolicies(nsX).
				Create(context.Background(), multiNetPolicy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Allowed
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podA))
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podB))
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podC))

			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsZ_podB))

			// Not allowed
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsZ_podA))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsZ_podC))

			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podA))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podB))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podC))
		})

		It("ALLOW traffic to nsX_podA only from (ns IN {nsY, nsZ} AND pod IN {podB, podC})", func() {

			multiNetPolicy := defineMultiNetworkPolicy(testsNetworkNamespace + "/" + testNetwork)
			multiNetPolicy.Spec = multinetpolicyv1.MultiNetworkPolicySpec{
				PolicyTypes: []multinetpolicyv1.MultiPolicyType{
					multinetpolicyv1.PolicyTypeIngress,
				},
				Ingress: []multinetpolicyv1.MultiNetworkPolicyIngressRule{
					{
						From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{{
									Key:      "kubernetes.io/metadata.name",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{nsY, nsZ},
								}},
							},
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{{
									Key:      "pod",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"b", "c"},
								}},
							}},
						},
					},
				},
				Egress: []multinetpolicyv1.MultiNetworkPolicyEgressRule{},
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				},
			}

			_, err := client.Client.MultiNetworkPolicies(nsX).
				Create(context.Background(), multiNetPolicy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Allowed
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podB))
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsY_podC))
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsZ_podB))
			Eventually(nsX_podA, "30s", "1s").Should(BeAbleToSendTrafficTo(nsZ_podC))

			// Not allowed
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podA))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podB))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsX_podC))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsY_podA))
			Eventually(nsX_podA, "30s", "1s").ShouldNot(BeAbleToSendTrafficTo(nsZ_podA))
		})
	})
})

func cleanPodsInNamespaces(argNamespaces ...string) {
	for _, ns := range argNamespaces {
		Expect(
			namespaces.CleanPods(ns, client.Client)).
			ToNot(HaveOccurred())
	}
}

func cleanMultiNetworkPolicies(namespace string) {
	err := client.Client.MultiNetworkPolicies(namespace).DeleteCollection(context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{})
	Expect(err).ToNot(HaveOccurred())

	Eventually(func() int {
		ret, err := client.Client.MultiNetworkPolicies(namespace).
			List(context.Background(), metav1.ListOptions{})
		Expect(err).ToNot(HaveOccurred())
		return len(ret.Items)
	}, 30*time.Second, 1*time.Second).Should(BeZero())

}

func createNamespaces(argNamespaces ...string) {
	for _, ns := range argNamespaces {
		Expect(
			namespaces.Create(ns, client.Client),
		).ToNot(HaveOccurred())
	}
}

func createPodsInNamespace(namespace string) (*corev1.Pod, *corev1.Pod, *corev1.Pod) {

	podA := pods.DefinePod(namespace)
	pods.RedefineWithLabel(podA, "pod", "a")
	pods.RedefinePodWithNetwork(podA, testsNetworkNamespace+"/"+testNetwork)
	redefineWithNetcatServer(podA)
	podA.ObjectMeta.GenerateName = "testpod-a-"
	podA = createAndStartPod(podA)

	podB := pods.DefinePod(namespace)
	pods.RedefineWithLabel(podB, "pod", "b")
	pods.RedefinePodWithNetwork(podB, testsNetworkNamespace+"/"+testNetwork)
	redefineWithNetcatServer(podB)
	podB.ObjectMeta.GenerateName = "testpod-b-"
	podB = createAndStartPod(podB)

	podC := pods.DefinePod(namespace)
	pods.RedefineWithLabel(podC, "pod", "c")
	pods.RedefinePodWithNetwork(podC, testsNetworkNamespace+"/"+testNetwork)
	redefineWithNetcatServer(podC)
	podC.ObjectMeta.GenerateName = "testpod-c-"
	podC = createAndStartPod(podC)

	return podA, podB, podC
}

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

func defineMultiNetworkPolicy(targetNetwork string) *multinetpolicyv1.MultiNetworkPolicy {
	ret := multinetpolicyv1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-multinetwork-policy-",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": targetNetwork,
			},
		},
	}

	return &ret
}

func redefineWithNetcatServer(pod *corev1.Pod) *corev1.Pod {
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    "netcat-server",
		Image:   images.For(images.TestUtils),
		Command: []string{"nc", "-k", "-l", "0.0.0.0", "5555"}})
	return pod
}

func createAndStartPod(pod *corev1.Pod) *corev1.Pod {
	res, err := client.Client.Pods(pod.Namespace).
		Create(context.Background(), pod, metav1.CreateOptions{})
	Expect(err).
		WithOffset(1).
		ToNot(HaveOccurred())

	Eventually(func() (corev1.PodPhase, error) {
		res, err = client.Client.Pods(res.Namespace).Get(context.Background(), res.Name, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred(), "Error while creating")
		return res.Status.Phase, err
	}, 1*time.Minute, 10*time.Second).
		WithOffset(1).
		Should(Equal(corev1.PodRunning))

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

	return canSendTraffic(sourcePod, m.destinationPod)
}

func (matcher *SendTrafficToMatcher) FailureMessage(actual interface{}) string {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return "SendTrafficToMatcher should be used against v1.Pod objects"
	}

	return fmt.Sprintf("pod [%s/%s] is not reachable by pod [%s/%s], but it should be",
		matcher.destinationPod.Namespace, matcher.destinationPod.Name, sourcePod.Namespace, sourcePod.Name)
}

func (matcher *SendTrafficToMatcher) NegatedFailureMessage(actual interface{}) string {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return "SendTrafficToMatcher should be used against v1.Pod objects"
	}

	return fmt.Sprintf("pod [%s/%s] is reachable by pod [%s/%s], but it shouldn't be",
		matcher.destinationPod.Namespace, matcher.destinationPod.Name, sourcePod.Namespace, sourcePod.Name)
}

func canSendTraffic(sourcePod, destinationPod *corev1.Pod) (bool, error) {
	destinationIps, err := network.GetSriovNicIPs(destinationPod, "net1")
	if err != nil {
		return false, fmt.Errorf("can't determine destination pod [%s] SR-IOV ip address: %w ", destinationPod.Name, err)
	}

	if len(destinationIps) == 0 {
		return false, fmt.Errorf("no ip address found for destination pod [%s] SR-IOV ip address: %w ", destinationPod.Name, err)
	}

	output, err := pods.ExecCommand(client.Client, *sourcePod, []string{"bash", "-c", fmt.Sprintf("echo xxx | nc -w 3 %s 5555", destinationIps[0])})
	if err != nil {
		if strings.Contains(output.String(), "Ncat: Connection timed out") {
			// Timeout error is symptom of no
			return false, nil
		}
		return false, fmt.Errorf("can't connect pods [%s] -> [%s]: %w ", sourcePod.Name, destinationPod.Name, err)
	}

	return true, nil
}

type connectivityPair struct {
	from  *corev1.Pod
	to    *corev1.Pod
	value bool
}

func printConnectivityMatrix(pods ...*corev1.Pod) {

	data := make(chan connectivityPair)

	connectivityMatrix := make(map[*corev1.Pod]map[*corev1.Pod]bool)
	go func() {
		for k := range data {
			//			fmt.Println(k)
			from, ok := connectivityMatrix[k.from]
			if !ok {
				from = make(map[*corev1.Pod]bool)
				connectivityMatrix[k.from] = from
			}
			from[k.to] = k.value
		}
	}()

	var wg sync.WaitGroup

	for _, source := range pods {
		for _, destination := range pods {
			wg.Add(1)
			d := destination
			s := source
			go func() {
				defer wg.Done()
				//connectivityStr := "-"
				if s == nil || d == nil {
					return
				}
				canReach, err := canSendTraffic(s, d)
				if err != nil {
					fmt.Println(err.Error())
				}
				//if err == nil && canReach {
				//	connectivityStr = "X"
				//}
				/*k := fmt.Sprintf("%s/%s -> %s/%s : %s",
					s.Namespace, s.Name,
					d.Namespace, d.Name,
					connectivityStr,
				)*/
				data <- connectivityPair{from: s, to: d, value: canReach}
			}()
		}
	}

	wg.Wait()
	close(data)

	for _, destination := range pods {
		fmt.Printf("\t%s", shortName(destination))
	}
	fmt.Println()

	for _, source := range pods {
		fmt.Printf("%s", shortName(source))
		from, ok := connectivityMatrix[source]
		if !ok {
			fmt.Println()
			continue
		}
		for _, destination := range pods {
			fmt.Printf("\t")
			canReach, ok := from[destination]
			if !ok {
				fmt.Printf("?")
				continue
			}
			if canReach {
				fmt.Printf("X")
				continue
			}

			fmt.Printf(".")
		}
		fmt.Println()
	}

}

func shortName(p *corev1.Pod) string {
	ns := ""
	switch p.Namespace {
	case nsX:
		ns = "x"
	case nsY:
		ns = "y"
	case nsZ:
		ns = "z"
	}

	podLabel, ok := p.ObjectMeta.Labels["pod"]
	if !ok {
		podLabel = "?"
	}
	return ns + "/" + podLabel
}
