/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package userspace

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/util"
	"k8s.io/kubernetes/pkg/util/slice"
)

var (
	ErrMissingServiceEntry = errors.New("missing service entry")
	ErrMissingEndpoints    = errors.New("missing endpoints")
)

var (
	Nodes         map[string]string
	Pods          map[string]*P
	BestNode      string
	EndpointsMap  map[string][]string
	NextEndpoints []string
	ResLists      map[string]ResourceList
)

type P struct {
	IP       string
	NodeName string
}

var (
	KUBERNETES_SERVICE_HOST = os.Getenv("KUBERNETES_SERVICE_HOST")
	KUBERNETES_SERVICE_PORT = os.Getenv("KUBERNETES_SERVICE_PORT")
)

var (
	CPU_THRESHOLD    = 0.8
	MEMORY_THRESHOLD = 0.8
	WEIGHT_CPU       = 0.4
	WEIGHT_MEMORY    = 0.5
	WEIGHT_LATENCY   = 0.1
)

type ResourceList struct {
	CPU     CPU
	Memory  Memory
	Latency int64
}

type affinityState struct {
	clientIP string
	//clientProtocol  api.Protocol //not yet used
	//sessionCookie   string       //not yet used
	endpoint string
	lastUsed time.Time
}

type affinityPolicy struct {
	affinityType v1.ServiceAffinity
	affinityMap  map[string]*affinityState // map client IP -> affinity info
	ttlSeconds   int
}

// LoadBalancerRR is a round-robin load balancer.
type LoadBalancerRR struct {
	lock     sync.RWMutex
	services map[proxy.ServicePortName]*balancerState
}

// Ensure this implements LoadBalancer.
var _ LoadBalancer = &LoadBalancerRR{}

type balancerState struct {
	endpoints []string // a list of "ip:port" style strings
	index     int      // current index into endpoints
	affinity  affinityPolicy
}
type NodeList struct {
	Items []Node `json:"items"`
}

type Node struct {
	Metadata NodeMetadata `json:"metadata"`
	Status   NodeStatus   `json:"status"`
}

type NodeMetadata struct {
	Name string `json:"name"`
}

type NodeStatus struct {
	Addresses []NodeAddress `json:"addresses"`
}

type NodeAddress struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

func getNodes() {
	fmt.Printf("Inside get nodes function")

	url := "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS") + "/api/v1/nodes"

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		fmt.Printf("Error reading CA certificate: %s\n", err)
		return
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Load the Service Account token for authentication
	token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Printf("Error reading service account token: %s\n", err)
		return
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching nodes: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return
	}

	var nodeList NodeList
	if err := json.Unmarshal(body, &nodeList); err != nil {
		fmt.Printf("Error unmarshaling nodes: %s\n", err)
		return
	}

	for _, node := range nodeList.Items {
		nodeName := node.Metadata.Name

		for _, address := range node.Status.Addresses {
			if address.Type == "InternalIP" {
				Nodes[nodeName] = address.Address
			}
		}
	}

	fmt.Printf("Nodes: %v\n", Nodes)
}

type PodList struct {
	Items []Pod `json:"items"`
}

type Pod struct {
	Metadata PodMetadata `json:"metadata"`
	Status   PodStatus   `json:"status"`
	Spec     PodSpec     `json:"spec"`
}

type PodMetadata struct {
	Name string `json:"name"`
}

type PodStatus struct {
	PodIP string `json:"podIP"`
}

type PodSpec struct {
	NodeName string `json:"nodeName"`
}

func getNodesFromPods() {
	fmt.Printf("Inside get nodes from pods function")

	url := "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS") + "/api/v1/pods"

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		fmt.Printf("Error reading CA certificate: %s\n", err)
		return
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Load the Service Account token for authentication
	token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Printf("Error reading service account token: %s\n", err)
		return
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching pods: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	var podList PodList
	err = json.Unmarshal(body, &podList)
	if err != nil {
		fmt.Printf("Error unmarshaling pods: %v\n", err)
		return
	}

	for _, pod := range podList.Items {
		Pods[pod.Metadata.Name] = &P{
			IP:       pod.Status.PodIP,
			NodeName: pod.Spec.NodeName,
		}
	}

	fmt.Printf("Pods: %v\n", Pods)
}

type Resources struct {
	Node map[string]interface{} `json:"node"`
	Pod  map[string]interface{} `json:"pod"`
}

type CPU struct {
	UsageNanoCores  int64 `json:"usageNanoCores"`
	UsageMilliCores int64 `json:"usageMilliCores"`
}

type Memory struct {
	UsageBytes     int64 `json:"usageBytes"`
	UsageMebiBytes int64 `json:"usageMebiBytes"`
}

func randomChoice(choices []string) string {
	if len(choices) == 0 {
		return ""
	}

	return choices[rand.Intn(len(choices))]
}

func getResourceMetrics(node string) {
	fmt.Printf("Inside get resource metrics function")

	rand.Seed(time.Now().UnixNano())

	Latencies := []string{"226", "375", "23"}

	url := "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS") + "/api/v1/nodes" + node + "/proxy/stats/summary"

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		fmt.Printf("Error reading CA certificate: %s\n", err)
		return
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Load the Service Account token for authentication
	token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Printf("Error reading service account token: %s\n", err)
		return
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching resource metrics: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	var resources Resources
	err = json.Unmarshal(body, &resources)
	if err != nil {
		fmt.Printf("Error unmarshaling resource metrics: %v\n", err)
		return
	}

	fmt.Printf("Resources: %v\n", resources)

	var cpu CPU
	var memory Memory
	latency := randomChoice(Latencies)

	cpu.UsageNanoCores = int64(resources.Node["cpu"].(map[string]interface{})["usageNanoCores"].(float64))
	memory.UsageBytes = int64(resources.Node["memory"].(map[string]interface{})["usageBytes"].(float64))

	cpu.UsageMilliCores = int64(cpu.UsageNanoCores / 1000000)
	memory.UsageMebiBytes = int64(memory.UsageBytes / 1048576)

	lat, err := strconv.ParseInt(latency, 10, 64)

	ResLists[node] = ResourceList{cpu, memory, lat}

	fmt.Printf("Resource List: %v\n", ResLists[node])
}

func getBestNode() {
	fmt.Printf("Inside get best node function")

	var bestNode string
	highestScore := 0

	for node := range Nodes {
		cpu := ResLists[node].CPU
		memory := ResLists[node].Memory

		fmt.Printf("CPU: %v\n", cpu)
		fmt.Printf("Memory: %v\n", memory)

		if float64(cpu.UsageMilliCores) < CPU_THRESHOLD && float64(memory.UsageMebiBytes) < MEMORY_THRESHOLD {
			score := WEIGHT_CPU*float64(cpu.UsageMilliCores) + WEIGHT_MEMORY*float64(memory.UsageMebiBytes) + WEIGHT_LATENCY*(float64(ResLists[node].Latency)/1000)

			if score > float64(highestScore) {
				highestScore = int(score)
				bestNode = node
			}
		}
	}

	BestNode = bestNode

	fmt.Printf("Best Node: %v\n", BestNode)
}

func newAffinityPolicy(affinityType v1.ServiceAffinity, ttlSeconds int) *affinityPolicy {
	return &affinityPolicy{
		affinityType: affinityType,
		affinityMap:  make(map[string]*affinityState),
		ttlSeconds:   ttlSeconds,
	}
}

// NewLoadBalancerRR returns a new LoadBalancerRR.
func NewLoadBalancerRR() *LoadBalancerRR {
	return &LoadBalancerRR{
		services: map[proxy.ServicePortName]*balancerState{},
	}
}

func (lb *LoadBalancerRR) NewService(svcPort proxy.ServicePortName, affinityType v1.ServiceAffinity, ttlSeconds int) error {
	klog.V(4).Infof("LoadBalancerRR NewService %q", svcPort)
	lb.lock.Lock()
	defer lb.lock.Unlock()
	lb.newServiceInternal(svcPort, affinityType, ttlSeconds)
	return nil
}

// This assumes that lb.lock is already held.
func (lb *LoadBalancerRR) newServiceInternal(svcPort proxy.ServicePortName, affinityType v1.ServiceAffinity, ttlSeconds int) *balancerState {
	if ttlSeconds == 0 {
		ttlSeconds = int(v1.DefaultClientIPServiceAffinitySeconds) //default to 3 hours if not specified.  Should 0 be unlimited instead????
	}

	if _, exists := lb.services[svcPort]; !exists {
		lb.services[svcPort] = &balancerState{affinity: *newAffinityPolicy(affinityType, ttlSeconds)}
		klog.V(4).Infof("LoadBalancerRR service %q did not exist, created", svcPort)
	} else if affinityType != "" {
		lb.services[svcPort].affinity.affinityType = affinityType
	}
	return lb.services[svcPort]
}

func (lb *LoadBalancerRR) DeleteService(svcPort proxy.ServicePortName) {
	klog.V(4).Infof("LoadBalancerRR DeleteService %q", svcPort)
	lb.lock.Lock()
	defer lb.lock.Unlock()
	delete(lb.services, svcPort)
}

// return true if this service is using some form of session affinity.
func isSessionAffinity(affinity *affinityPolicy) bool {
	// Should never be empty string, but checking for it to be safe.
	if affinity.affinityType == "" || affinity.affinityType == v1.ServiceAffinityNone {
		return false
	}
	return true
}

// ServiceHasEndpoints checks whether a service entry has endpoints.
func (lb *LoadBalancerRR) ServiceHasEndpoints(svcPort proxy.ServicePortName) bool {
	lb.lock.RLock()
	defer lb.lock.RUnlock()
	state, exists := lb.services[svcPort]
	// TODO: while nothing ever assigns nil to the map, *some* of the code using the map
	// checks for it.  The code should all follow the same convention.
	return exists && state != nil && len(state.endpoints) > 0
}

func getPodsFromNode(node string) []string {
	fmt.Printf("Inside get pods from node function")

	var pods []string

	for pod, p := range Pods {
		if p.NodeName == node {
			pods = append(pods, pod)
		}
	}

	fmt.Printf("Pods: %v\n", pods)

	return pods
}

func getServiceEndpoints(svcPort proxy.ServicePortName) []string {
	fmt.Printf("Inside get service endpoints function")

	url := "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS") + "/api/v1/namespaces/" + svcPort.NamespacedName.Namespace + "/endpoints/" + svcPort.NamespacedName.Name

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		fmt.Printf("Error reading CA certificate: %s\n", err)
		return nil
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Load the Service Account token for authentication
	token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Printf("Error reading service account token: %s\n", err)
		return nil
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching endpoints: %s\n", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil
	}

	var endpoints v1.Endpoints
	err = json.Unmarshal(body, &endpoints)
	if err != nil {
		fmt.Printf("Error unmarshaling endpoints: %v\n", err)
		return nil
	}

	var endpointsList []string

	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			endpointsList = append(endpointsList, address.IP)
		}
	}

	fmt.Printf("Endpoints: %v\n", endpointsList)

	return endpointsList
}

func common(pods []string, endpoints []string) []string {
	fmt.Printf("Inside common function")

	var common []string
	var ips []string

	for _, pod := range pods {
		ips = append(ips, Pods[pod].IP)
	}

	elementMap := make(map[string]bool)
	for _, item := range ips {
		elementMap[item] = true
	}

	for _, item := range endpoints {
		if _, found := elementMap[item]; found {
			common = append(common, item)
		}
	}

	fmt.Printf("Common: %v\n", common)

	return common
}

// NextEndpoint returns a service endpoint.
// The service endpoint is chosen using the round-robin algorithm.
func (lb *LoadBalancerRR) NextEndpoint(svcPort proxy.ServicePortName, srcAddr net.Addr, sessionAffinityReset bool) (string, error) {
	// Coarse locking is simple.  We can get more fine-grained if/when we
	// can prove it matters.

	fmt.Printf("Inside next endpoint function")

	lb.lock.Lock()
	defer lb.lock.Unlock()

	state, exists := lb.services[svcPort]
	if !exists || state == nil {
		return "", ErrMissingServiceEntry
	}
	if len(state.endpoints) == 0 {
		return "", ErrMissingEndpoints
	}
	klog.V(4).Infof("NextEndpoint for service %q, srcAddr=%v: endpoints: %+v", svcPort, srcAddr, state.endpoints)

	sessionAffinityEnabled := isSessionAffinity(&state.affinity)

	var ipaddr string
	if sessionAffinityEnabled {
		// Caution: don't shadow ipaddr
		var err error
		ipaddr, _, err = net.SplitHostPort(srcAddr.String())
		if err != nil {
			return "", fmt.Errorf("malformed source address %q: %v", srcAddr.String(), err)
		}
		if !sessionAffinityReset {
			sessionAffinity, exists := state.affinity.affinityMap[ipaddr]
			if exists && int(time.Since(sessionAffinity.lastUsed).Seconds()) < state.affinity.ttlSeconds {
				// Affinity wins.
				endpoint := sessionAffinity.endpoint
				sessionAffinity.lastUsed = time.Now()
				klog.V(4).Infof("NextEndpoint for service %q from IP %s with sessionAffinity %#v: %s", svcPort, ipaddr, sessionAffinity, endpoint)
				return endpoint, nil
			}
		}
	}

	fmt.Printf("Our code starts here...")

	getNodes()
	getNodesFromPods()

	for node := range Nodes {
		fmt.Printf("Node: %v\n", node)

		getResourceMetrics(node)
	}

	getBestNode()

	currentPod := os.Getenv("POD_NAME")
	currentNode := Pods[currentPod].NodeName

	fmt.Printf("Current Node: %v\n", currentNode)

	var nextNode string

	if float64(ResLists[currentNode].CPU.UsageMilliCores) < CPU_THRESHOLD && float64(ResLists[currentNode].Memory.UsageMebiBytes) < MEMORY_THRESHOLD {
		nextNode = currentNode
	} else {
		nextNode = BestNode
	}

	fmt.Printf("Next Node: %v\n", nextNode)

	pods := getPodsFromNode(nextNode)

	endpoints := getServiceEndpoints(svcPort)

	NextEndpoints = common(pods, endpoints)

	fmt.Printf("Next Endpoints: %v\n", NextEndpoints)

	if len(NextEndpoints) == 0 {
		return "", ErrMissingEndpoints
	}

	endpoint := randomChoice(NextEndpoints)

	fmt.Printf("Endpoint: %v\n", endpoint)

	// Fetch the pod's endpoint

	// endpoint := state.endpoints[state.index]
	state.index = (state.index + 1) % len(state.endpoints)

	if sessionAffinityEnabled {
		var affinity *affinityState
		affinity = state.affinity.affinityMap[ipaddr]
		if affinity == nil {
			affinity = new(affinityState) //&affinityState{ipaddr, "TCP", "", endpoint, time.Now()}
			state.affinity.affinityMap[ipaddr] = affinity
		}
		affinity.lastUsed = time.Now()
		affinity.endpoint = endpoint
		affinity.clientIP = ipaddr
		klog.V(4).Infof("Updated affinity key %s: %#v", ipaddr, state.affinity.affinityMap[ipaddr])
	}

	return endpoint, nil
}

// Remove any session affinity records associated to a particular endpoint (for example when a pod goes down).
func removeSessionAffinityByEndpoint(state *balancerState, svcPort proxy.ServicePortName, endpoint string) {
	for _, affinity := range state.affinity.affinityMap {
		if affinity.endpoint == endpoint {
			klog.V(4).Infof("Removing client: %s from affinityMap for service %q", affinity.endpoint, svcPort)
			delete(state.affinity.affinityMap, affinity.clientIP)
		}
	}
}

// Loop through the valid endpoints and then the endpoints associated with the Load Balancer.
// Then remove any session affinity records that are not in both lists.
// This assumes the lb.lock is held.
func (lb *LoadBalancerRR) removeStaleAffinity(svcPort proxy.ServicePortName, newEndpoints []string) {
	newEndpointsSet := sets.NewString()
	for _, newEndpoint := range newEndpoints {
		newEndpointsSet.Insert(newEndpoint)
	}

	state, exists := lb.services[svcPort]
	if !exists {
		return
	}
	for _, existingEndpoint := range state.endpoints {
		if !newEndpointsSet.Has(existingEndpoint) {
			klog.V(2).Infof("Delete endpoint %s for service %q", existingEndpoint, svcPort)
			removeSessionAffinityByEndpoint(state, svcPort, existingEndpoint)
		}
	}
}

func (lb *LoadBalancerRR) OnEndpointsAdd(endpoints *v1.Endpoints) {
	portsToEndpoints := util.BuildPortsToEndpointsMap(endpoints)

	lb.lock.Lock()
	defer lb.lock.Unlock()

	for portname := range portsToEndpoints {
		svcPort := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}, Port: portname}
		newEndpoints := portsToEndpoints[portname]
		state, exists := lb.services[svcPort]

		if !exists || state == nil || len(newEndpoints) > 0 {
			klog.V(1).Infof("LoadBalancerRR: Setting endpoints for %s to %+v", svcPort, newEndpoints)
			// OnEndpointsAdd can be called without NewService being called externally.
			// To be safe we will call it here.  A new service will only be created
			// if one does not already exist.
			state = lb.newServiceInternal(svcPort, v1.ServiceAffinity(""), 0)
			state.endpoints = util.ShuffleStrings(newEndpoints)

			// Reset the round-robin index.
			state.index = 0
		}
	}
}

func (lb *LoadBalancerRR) OnEndpointsUpdate(oldEndpoints, endpoints *v1.Endpoints) {
	portsToEndpoints := util.BuildPortsToEndpointsMap(endpoints)
	oldPortsToEndpoints := util.BuildPortsToEndpointsMap(oldEndpoints)
	registeredEndpoints := make(map[proxy.ServicePortName]bool)

	lb.lock.Lock()
	defer lb.lock.Unlock()

	for portname := range portsToEndpoints {
		svcPort := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}, Port: portname}
		newEndpoints := portsToEndpoints[portname]
		state, exists := lb.services[svcPort]

		curEndpoints := []string{}
		if state != nil {
			curEndpoints = state.endpoints
		}

		if !exists || state == nil || len(curEndpoints) != len(newEndpoints) || !slicesEquiv(slice.CopyStrings(curEndpoints), newEndpoints) {
			klog.V(1).Infof("LoadBalancerRR: Setting endpoints for %s to %+v", svcPort, newEndpoints)
			lb.removeStaleAffinity(svcPort, newEndpoints)
			// OnEndpointsUpdate can be called without NewService being called externally.
			// To be safe we will call it here.  A new service will only be created
			// if one does not already exist.  The affinity will be updated
			// later, once NewService is called.
			state = lb.newServiceInternal(svcPort, v1.ServiceAffinity(""), 0)
			state.endpoints = util.ShuffleStrings(newEndpoints)

			// Reset the round-robin index.
			state.index = 0
		}
		registeredEndpoints[svcPort] = true
	}

	// Now remove all endpoints missing from the update.
	for portname := range oldPortsToEndpoints {
		svcPort := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: oldEndpoints.Namespace, Name: oldEndpoints.Name}, Port: portname}
		if _, exists := registeredEndpoints[svcPort]; !exists {
			lb.resetService(svcPort)
		}
	}
}

func (lb *LoadBalancerRR) resetService(svcPort proxy.ServicePortName) {
	// If the service is still around, reset but don't delete.
	if state, ok := lb.services[svcPort]; ok {
		if len(state.endpoints) > 0 {
			klog.V(2).Infof("LoadBalancerRR: Removing endpoints for %s", svcPort)
			state.endpoints = []string{}
		}
		state.index = 0
		state.affinity.affinityMap = map[string]*affinityState{}
	}
}

func (lb *LoadBalancerRR) OnEndpointsDelete(endpoints *v1.Endpoints) {
	portsToEndpoints := util.BuildPortsToEndpointsMap(endpoints)

	lb.lock.Lock()
	defer lb.lock.Unlock()

	for portname := range portsToEndpoints {
		svcPort := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}, Port: portname}
		lb.resetService(svcPort)
	}
}

func (lb *LoadBalancerRR) OnEndpointsSynced() {
}

// Tests whether two slices are equivalent.  This sorts both slices in-place.
func slicesEquiv(lhs, rhs []string) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	if reflect.DeepEqual(slice.SortStrings(lhs), slice.SortStrings(rhs)) {
		return true
	}
	return false
}

func (lb *LoadBalancerRR) CleanupStaleStickySessions(svcPort proxy.ServicePortName) {
	lb.lock.Lock()
	defer lb.lock.Unlock()

	state, exists := lb.services[svcPort]
	if !exists {
		return
	}
	for ip, affinity := range state.affinity.affinityMap {
		if int(time.Since(affinity.lastUsed).Seconds()) >= state.affinity.ttlSeconds {
			klog.V(4).Infof("Removing client %s from affinityMap for service %q", affinity.clientIP, svcPort)
			delete(state.affinity.affinityMap, ip)
		}
	}
}
