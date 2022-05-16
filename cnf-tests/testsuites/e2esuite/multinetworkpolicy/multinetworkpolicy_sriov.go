package multinetworkpolicy

import (
	"context"
	"fmt"
	"math/rand"
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
	"k8s.io/apimachinery/pkg/util/intstr"

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

var port5555 intstr.IntOrString = intstr.FromInt(5555)
var port6666 intstr.IntOrString = intstr.FromInt(6666)
var protoTCP corev1.Protocol = corev1.ProtocolTCP
var protoUDP corev1.Protocol = corev1.ProtocolUDP

// TODO - remove this: https://github.com/kubernetes/kubernetes/blob/master/test/e2e/network/netpol/network_policy.go

var nsX_podA, nsX_podB, nsX_podC *corev1.Pod
var nsY_podA, nsY_podB, nsY_podC *corev1.Pod
var nsZ_podA, nsZ_podB, nsZ_podC *corev1.Pod

var _ = Describe("[multinetworkpolicy] [sriov] integration", func() {

	sriovclient := sriovtestclient.New("")

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

		// TODO remove
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

			// fmt.Println("Debug ...")
			// fmt.Scanln()
		}

	})

	Context("Ingress", func() {
		It("DENY all traffic to a pod", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithEmptyIngressRules(),
				CreateInNamespace(nsX),
			)

			// Pod B and C are not affected by the policy
			eventually30s(nsX_podB).Should(Reach(nsX_podC))

			// Pod A should not be reacheable by B and C
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA))
			eventually30s(nsX_podC).ShouldNot(Reach(nsX_podA))
		})

		It("DENY all traffic to/from/in a namespace", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithEmptyIngressRules(),
				CreateInNamespace(nsX),
			)

			// Traffic within nsX is not allowed
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podB))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podC))
			eventually30s(nsX_podC).ShouldNot(Reach(nsX_podA))

			// Traffic to/from nsX is not allowed
			eventually30s(nsX_podA).ShouldNot(Reach(nsY_podA))
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podA))

			// Traffic within other namespaces is allowed
			eventually30s(nsY_podA).Should(Reach(nsY_podB))
			eventually30s(nsZ_podA).Should(Reach(nsZ_podB))

			// Traffic between other namespaces is allowed
			eventually30s(nsY_podA).Should(Reach(nsZ_podA))
			eventually30s(nsZ_podB).Should(Reach(nsY_podC))
		})

		It("ALLOW traffic to nsX_podA only from nsX_podB", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// The subject of test case
			eventually30s(nsX_podB).Should(Reach(nsX_podA))
			eventually30s(nsX_podC).ShouldNot(Reach(nsX_podA))

			// Traffic that should not be affected
			eventually30s(nsX_podB).Should(Reach(nsX_podC))
		})

		It("ALLOW traffic to nsX_podA only from (namespace == nsY)", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kubernetes.io/metadata.name": nsY,
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podA).Should(Reach(nsY_podA))
			eventually30s(nsX_podA).Should(Reach(nsY_podB))
			eventually30s(nsX_podA).Should(Reach(nsY_podC))

			// Not allowed
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podA))
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podB))
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podC))

			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podB))
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podC))
		})

		It("ALLOW traffic to nsX_podA only from (nsY/* OR */podB)", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
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
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podA).Should(Reach(nsY_podA))
			eventually30s(nsX_podA).Should(Reach(nsY_podB))
			eventually30s(nsX_podA).Should(Reach(nsY_podC))

			eventually30s(nsX_podA).Should(Reach(nsZ_podB))
			eventually30s(nsX_podA).Should(Reach(nsX_podB))

			// Not allowed
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podA))
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podC))

			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podC))
		})

		It("ALLOW traffic to nsX_podA only from (namespace IN {nsY, nsZ} AND pod IN {podB, podC})", func() {

			Skip("LabelSelectorwith multiple In values is not yet supported by multi-networkpolicy-iptables")
			//	E0511 14:37:07.698115       1 policyrules.go:238] pod selector: operator "In" without a single value cannot be converted into the old label selector format

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
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
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podA).Should(Reach(nsY_podB))
			eventually30s(nsX_podA).Should(Reach(nsY_podC))
			eventually30s(nsX_podA).Should(Reach(nsZ_podB))
			eventually30s(nsX_podA).Should(Reach(nsZ_podC))

			// Not allowed
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podA))
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podB))
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podC))

			eventually30s(nsX_podA).ShouldNot(Reach(nsY_podA))
			eventually30s(nsX_podA).ShouldNot(Reach(nsZ_podA))
		})
	})

	Context("Egress", func() {

		It("DENY all traffic from a pod", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithEmptyEgressRules(),
				CreateInNamespace(nsX),
			)

			// Pod B and C are not affected by the policy
			eventually30s(nsX_podB).Should(Reach(nsX_podC))

			// Pod A should not be reacheable by B and C
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podB))
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podB))
		})

		It("ALLOW traffic to nsX_podA only from nsX_podB", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithEgressRule(multinetpolicyv1.MultiNetworkPolicyEgressRule{
					To: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// The subject of test case
			eventually30s(nsX_podA).Should(Reach(nsX_podB))
			eventually30s(nsX_podA).ShouldNot(Reach(nsX_podC))

			// Traffic that should not be affected
			eventually30s(nsX_podB).Should(Reach(nsX_podC))
		})
	})

	Context("Stacked policies", func() {

		It("enforce multiple stacked policies with overlapping selector [nsX_podA <=> (nsY/* OR */podB)]", func() {

			Skip("Stacked policies are not yet supported")

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kubernetes.io/metadata.name": nsY,
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed all connection from nsY
			eventually30s(nsY_podA).Should(Reach(nsX_podA))
			eventually30s(nsY_podB).Should(Reach(nsX_podA))
			eventually30s(nsY_podC).Should(Reach(nsX_podA))

			// Allowed all connection from podB
			eventually30s(nsZ_podB).Should(Reach(nsX_podA))
			eventually30s(nsX_podB).Should(Reach(nsX_podA))

			// Not allowed
			eventually30s(nsZ_podA).ShouldNot(Reach(nsX_podA))
			eventually30s(nsZ_podC).ShouldNot(Reach(nsX_podA))

			eventually30s(nsX_podC).ShouldNot(Reach(nsX_podA))
		})

		It("enforce multiple stacked policies with overlapping selector and different ports (*/podB ==> nsX/podA:5555 , */podC ==> nsX/podA:6666)", func() {

			Skip("Stacked policies are not yet supported")

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &port5555,
						Protocol: &protoTCP,
					}},
				}),
				CreateInNamespace(nsX),
			)

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "c",
							},
						},
					}},
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &port6666,
						Protocol: &protoTCP,
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podB).Should(Reach(nsX_podA, OnPort(port5555)))
			eventually30s(nsY_podB).Should(Reach(nsX_podA, OnPort(port5555)))
			eventually30s(nsZ_podB).Should(Reach(nsX_podA, OnPort(port5555)))

			eventually30s(nsX_podC).Should(Reach(nsX_podA, OnPort(port6666)))
			eventually30s(nsY_podC).Should(Reach(nsX_podA, OnPort(port6666)))
			eventually30s(nsZ_podC).Should(Reach(nsX_podA, OnPort(port6666)))

			// Not allowed
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666)))
			eventually30s(nsY_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666)))
			eventually30s(nsZ_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666)))

			eventually30s(nsX_podC).ShouldNot(Reach(nsX_podA, OnPort(port5555)))
			eventually30s(nsY_podC).ShouldNot(Reach(nsX_podA, OnPort(port5555)))
			eventually30s(nsZ_podC).ShouldNot(Reach(nsX_podA, OnPort(port5555)))
		})
	})

	Context("Ports/Protocol", func() {
		It("Allow access only to a specific port/protocol TCP", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &port5555, // Default protocol: TCP
						Protocol: &protoTCP,
					}},
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podB).Should(Reach(nsX_podA, OnPort(port5555), ViaTCP))

			// Not allowed
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666), ViaTCP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666), ViaUDP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port5555), ViaUDP))
		})

		It("Allow access only to a specific port/protocol UDP", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &port6666,
						Protocol: &protoUDP,
					}},
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podB).Should(Reach(nsX_podA, OnPort(port6666), ViaUDP))

			// Not allowed
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port5555), ViaTCP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666), ViaTCP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port5555), ViaUDP))
		})

		It("Allow access only to a specific port/protocol TCP+UDP", func() {

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &port5555, // Default protocol: TCP
						Protocol: &protoTCP,
					}, {
						Port:     &port6666,
						Protocol: &protoUDP,
					}},
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podB).Should(Reach(nsX_podA, OnPort(port5555), ViaTCP))
			eventually30s(nsX_podB).Should(Reach(nsX_podA, OnPort(port6666), ViaUDP))

			// Not allowed
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666), ViaTCP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port5555), ViaUDP))
		})

		It("Allow access only to a specific UDP port from any pod", func() {

			//Skip("Rules with Port selector and without From are not supported")

			makeMultiNetworkPolicy(testsNetworkNamespace+"/"+testNetwork,
				WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &port6666,
						Protocol: &protoUDP,
					}},
				}),
				CreateInNamespace(nsX),
			)

			// Allowed
			eventually30s(nsX_podB).Should(Reach(nsX_podA, OnPort(port6666), ViaUDP))

			// Not allowed
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port5555), ViaTCP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port5555), ViaUDP))
			eventually30s(nsX_podB).ShouldNot(Reach(nsX_podA, OnPort(port6666), ViaTCP))
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
	redefineWithNetcatServers(podA)
	_, err := pods.RedefineAsPrivileged(podA, "")
	Expect(err).To(BeNil())
	podA.ObjectMeta.GenerateName = "testpod-a-"
	podA = createAndStartPod(podA)

	podB := pods.DefinePod(namespace)
	pods.RedefineWithLabel(podB, "pod", "b")
	pods.RedefinePodWithNetwork(podB, testsNetworkNamespace+"/"+testNetwork)
	redefineWithNetcatServers(podB)
	_, err = pods.RedefineAsPrivileged(podB, "")
	Expect(err).To(BeNil())
	podB.ObjectMeta.GenerateName = "testpod-b-"
	podB = createAndStartPod(podB)

	podC := pods.DefinePod(namespace)
	pods.RedefineWithLabel(podC, "pod", "c")
	pods.RedefinePodWithNetwork(podC, testsNetworkNamespace+"/"+testNetwork)
	redefineWithNetcatServers(podC)
	_, err = pods.RedefineAsPrivileged(podC, "")
	Expect(err).To(BeNil())
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

type MultiNetworkPolicyOpt func(*multinetpolicyv1.MultiNetworkPolicy)

func WithPodSelector(podSelector metav1.LabelSelector) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PodSelector = podSelector
	}
}

func WithEmptyIngressRules() MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeIngress)
		pol.Spec.Ingress = []multinetpolicyv1.MultiNetworkPolicyIngressRule{}
	}
}

func WithIngressRule(rule multinetpolicyv1.MultiNetworkPolicyIngressRule) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeIngress)
		pol.Spec.Ingress = append(pol.Spec.Ingress, rule)
	}
}

func WithEmptyEgressRules() MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeEgress)
		pol.Spec.Egress = []multinetpolicyv1.MultiNetworkPolicyEgressRule{}
	}
}

func WithEgressRule(rule multinetpolicyv1.MultiNetworkPolicyEgressRule) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeEgress)
		pol.Spec.Egress = append(pol.Spec.Egress, rule)
	}
}

func CreateInNamespace(ns string) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		ret, err := client.Client.MultiNetworkPolicies(ns).
			Create(context.Background(), pol, metav1.CreateOptions{})

		Expect(err).ToNot(HaveOccurred())

		ret.DeepCopyInto(pol)
	}
}

func makeMultiNetworkPolicy(targetNetwork string, opts ...MultiNetworkPolicyOpt) *multinetpolicyv1.MultiNetworkPolicy {
	ret := multinetpolicyv1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-multinetwork-policy-",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": targetNetwork,
			},
		},
	}

	for _, opt := range opts {
		opt(&ret)
	}

	return &ret
}

func redefineWithNetcatServers(pod *corev1.Pod) *corev1.Pod {
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    "netcat-tcp-server-5555",
		Image:   images.For(images.TestUtils),
		Command: []string{"nc", "--keep-open", "--listen", "0.0.0.0", "5555"}})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    "netcat-udp-server-5555",
		Image:   images.For(images.TestUtils),
		Command: []string{"nc", "--keep-open", "--udp", "--sh-exec", "/bin/cat >&2", "--listen", "0.0.0.0", "5555"}})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    "netcat-tcp-server-6666",
		Image:   images.For(images.TestUtils),
		Command: []string{"nc", "--keep-open", "--listen", "0.0.0.0", "6666"}})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    "netcat-udp-server-6666",
		Image:   images.For(images.TestUtils),
		Command: []string{"nc", "--keep-open", "--udp", "--sh-exec", "/bin/cat >&2", "--listen", "0.0.0.0", "6666"}})
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

type ReachOpt func(*ReachMatcher)

// Reach matcher allows making assertion on pod connectivity
func Reach(destinationPod *corev1.Pod, opts ...ReachOpt) types.GomegaMatcher {
	ret := &ReachMatcher{
		destinationPod:  destinationPod,
		destinationPort: port5555.String(),
		protocol:        protoTCP,
	}

	for _, opt := range opts {
		opt(ret)
	}

	return ret
}

func OnPort(port intstr.IntOrString) ReachOpt {
	return func(s *ReachMatcher) {
		s.destinationPort = port.String()
	}
}

var ViaTCP ReachOpt = func(s *ReachMatcher) {
	s.protocol = corev1.ProtocolTCP
}

var ViaUDP ReachOpt = func(s *ReachMatcher) {
	s.protocol = corev1.ProtocolUDP
}

type ReachMatcher struct {
	destinationPod  *corev1.Pod
	destinationPort string
	protocol        corev1.Protocol
}

func (m *ReachMatcher) Match(actual interface{}) (bool, error) {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return false, fmt.Errorf("ReachMatcher must be passed an *Pod. Got\n%s", format.Object(actual, 1))
	}

	return canSendTraffic(sourcePod, m.destinationPod, m.destinationPort, m.protocol)
}

func (m *ReachMatcher) FailureMessage(actual interface{}) string {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return "ReachMatcher should be used against v1.Pod objects"
	}

	return fmt.Sprintf(`pod [%s/%s %s] is not reachable by pod [%s/%s %s] on port[%s:%s], but it should be.
%s
Destination iptables:
%s
-----
Source iptables:
%s`,
		m.destinationPod.Namespace, m.destinationPod.Name, getFirstSriovNicIP(m.destinationPod),
		sourcePod.Namespace, sourcePod.Name, getFirstSriovNicIP(sourcePod),
		m.protocol, m.destinationPort,
		printConnectivityMatrix(m.destinationPort, m.protocol,
			nsX_podA, nsX_podB, nsX_podC,
			nsY_podA, nsY_podB, nsY_podC,
			nsZ_podA, nsZ_podB, nsZ_podC,
		),
		getIPTables(m.destinationPod),
		getIPTables(sourcePod),
	)
}

func (m *ReachMatcher) NegatedFailureMessage(actual interface{}) string {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return "ReachMatcher should be used against v1.Pod objects"
	}

	return fmt.Sprintf(`pod [%s/%s %s] is reachable by pod [%s/%s %s] on port[%s:%s], but it shouldn't be.
%s
Destination iptables:
%s
-----
Source iptables:
%s`,
		m.destinationPod.Namespace, m.destinationPod.Name, getFirstSriovNicIP(m.destinationPod),
		sourcePod.Namespace, sourcePod.Name, getFirstSriovNicIP(sourcePod),
		m.protocol, m.destinationPort,
		printConnectivityMatrix(m.destinationPort, m.protocol,
			nsX_podA, nsX_podB, nsX_podC,
			nsY_podA, nsY_podB, nsY_podC,
			nsZ_podA, nsZ_podB, nsZ_podC,
		),
		getIPTables(m.destinationPod),
		getIPTables(sourcePod),
	)
}

func canSendTraffic(sourcePod, destinationPod *corev1.Pod, destinationPort string, protocol corev1.Protocol) (bool, error) {
	destinationIps, err := network.GetSriovNicIPs(destinationPod, "net1")
	if err != nil {
		return false, fmt.Errorf("can't determine destination pod [%s] SR-IOV ip address: %w ", destinationPod.Name, err)
	}

	if len(destinationIps) == 0 {
		return false, fmt.Errorf("no ip address found for destination pod [%s] SR-IOV ip address: %w ", destinationPod.Name, err)
	}

	protocolArg := ""
	if protocol == corev1.ProtocolUDP {
		protocolArg = "--udp"
	}

	saltString := fmt.Sprintf("%d", rand.Intn(1000000)+1000000)

	output, err := pods.ExecCommand(
		client.Client,
		*sourcePod,
		[]string{
			"bash", "-c",
			fmt.Sprintf("echo %s %s-%s:%s%s | nc -w 3 %s %s %s",
				saltString,
				getFirstSriovNicIP(sourcePod),
				destinationIps[0],
				destinationPort,
				protocol,
				protocolArg,
				destinationIps[0],
				destinationPort,
			),
		})

	if err != nil {
		if protocol == corev1.ProtocolTCP && strings.Contains(output.String(), "Ncat: Connection timed out") {
			// Timeout error is symptom of no connection
			return false, nil
		}

		if protocol == corev1.ProtocolUDP && strings.Contains(output.String(), "Ncat: Connection refused") {
			return false, nil
		}

		return false, fmt.Errorf("can't connect pods [%s] -> [%s]: %w ", sourcePod.Name, destinationPod.Name, err)
	}

	destinationContainerName := fmt.Sprintf("netcat-%s-server-%s", strings.ToLower(string(protocol)), destinationPort)
	destinationLogs, err := pods.GetLogForContainer(
		destinationPod,
		destinationContainerName,
	)
	if err != nil {
		return false, fmt.Errorf("can't get destination pod logs [%s/%s]: %w ", destinationPod.Name, destinationContainerName, err)
	}

	if strings.Contains(destinationLogs, saltString) {
		return true, nil
	}
	return false, nil
}

// printConnectivityMatrix returns a string representation of the connectivity matrix between
// specified pods. The following is a sample output:
//
//  Reachability matrix of 9 pods on UDP:5555 (X = true, . = false)
//        x/a     x/b     x/c     y/a     y/b     y/c     z/a     z/b     z/c
//  x/a   X       X       X       X       X       X       X       X       X
//  x/b   X       .       X       X       X       X       X       X       X
//  x/c   X       X       .       X       X       X       X       X       X
//  y/a   X       X       X       X       X       X       X       X       X
//  y/b   X       X       X       X       .       X       X       X       X
//  y/c   X       X       X       X       X       .       X       X       X
//  z/a   X       X       X       X       X       X       .       X       X
//  z/b   X       X       X       X       X       X       X       .       X
//  z/c   X       X       X       X       X       X       X       X       .
func printConnectivityMatrix(destinationPort string, protocol corev1.Protocol, pods ...*corev1.Pod) string {

	type connectivityPair struct {
		from  *corev1.Pod
		to    *corev1.Pod
		value bool
	}

	data := make(chan connectivityPair, 81)

	connectivityMatrix := make(map[*corev1.Pod]map[*corev1.Pod]bool)

	var conversionWG sync.WaitGroup
	conversionWG.Add(1)
	go func() {
		defer conversionWG.Done()
		for k := range data {
			from, ok := connectivityMatrix[k.from]
			if !ok {
				from = make(map[*corev1.Pod]bool)
				connectivityMatrix[k.from] = from
			}
			from[k.to] = k.value
		}
	}()

	var producerWG sync.WaitGroup

	for _, source := range pods {
		for _, destination := range pods {
			producerWG.Add(1)
			d := destination
			s := source
			go func() {
				defer producerWG.Done()
				//connectivityStr := "-"
				if s == nil || d == nil {
					return
				}
				canReach, err := canSendTraffic(s, d, destinationPort, protocol) // TODO
				if err != nil {
					fmt.Println(err.Error())
					return
				}

				data <- connectivityPair{from: s, to: d, value: canReach}
			}()
		}
	}

	producerWG.Wait()
	close(data)
	conversionWG.Wait()

	ret := fmt.Sprintf("Reachability matrix of %d pods on %s:%s (X = true, . = false)\n", len(pods), protocol, destinationPort)

	for _, destination := range pods {
		ret += fmt.Sprintf("\t%s", shortName(destination))
	}
	ret += "\n"

	for _, source := range pods {
		ret += shortName(source)
		from, ok := connectivityMatrix[source]
		if !ok {
			ret += "\n"
			continue
		}
		for _, destination := range pods {
			ret += "\t"
			canReach, ok := from[destination]
			if !ok {
				ret += "?"
				continue
			}
			if canReach {
				ret += "X"
				continue
			}

			ret += "."
		}
		ret += "\n"
	}

	return ret
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

func appendIfNotPresent(input []multinetpolicyv1.MultiPolicyType, newElement multinetpolicyv1.MultiPolicyType) []multinetpolicyv1.MultiPolicyType {
	for _, e := range input {
		if e == newElement {
			return input
		}
	}

	return append(input, newElement)
}

func eventually30s(actual interface{}) AsyncAssertion {
	return Eventually(actual, "30s", "1s")
}

func getFirstSriovNicIP(pod *corev1.Pod) string {
	ips, err := network.GetSriovNicIPs(pod, "net1")
	if err != nil {
		return "<err: " + err.Error() + ">"
	}

	if len(ips) == 0 {
		return "<no IP>"
	}

	return ips[0]
}

func getIPTables(pod *corev1.Pod) string {
	output, err := pods.ExecCommand(client.Client, *pod, []string{"iptables", "-L", "-v", "-n"})
	if err != nil {
		return "<err: " + err.Error() + ">"
	}

	return output.String()
}
