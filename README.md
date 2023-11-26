# CSL7510-VCC-Project

## Implementation of RAP ( Resource Adaptive Proxy)

### What is Resource Adaptive Proxy
Resource Adaptive Proxy (RAP) enhances load balancing by periodically monitoring the resource and network status of each pod and worker node in a K8s cluster. It prioritizes local handling of requests and, if the local node is overloaded, intelligently forwards requests to the best-performing node in the cluster, considering resource availability. Experimental results demonstrate that RAP significantly improves throughput and reduces request latency compared to K8s' default load-balancing mechanism.

For knowing more about RAP, refer to https://www.mdpi.com/1424-8220/22/8/2869.

### Adding RAP to K8s cluster
There are some prerequisites for adding RAP to your cluster. For RAP to work, you need to enable the `userspace` mode. Now, the `userspace` mode is deprecated in Kubernetes v1.23, therefore, we are using [Kubernetes 1.21.10](https://github.com/kubernetes/kubernetes/tree/release-1.21). Also, install [Golang](https://go.dev/doc/install) in your workstation. 

- Create 3 nodes with 1 master node and 2 worker nodes
  - We have used GCP for creating the instances at different locations and used the provided terraform code for launching the instances
  - Launch the K8s cluster with [kubeadm](https://v1-24.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/).
- Now build the `kube-proxy` with the RAP code
  - Go ahead and clone the `release-1.21` being checked out.
    ```
    git clone --branch release-1.21 https://github.com/kubernetes/kubernetes.git
    ```
  - change the code at `pkg/proxy/userspace/roundrobin.go` with the code provided at `rap.go`
  - Now build the `kube-proxy` with the command at the root of the repository
    ```
    make kube-proxy
    ```
  - Now build the docker image with the new kube-proxy.
    - Now let's go ahead and build the new docker image with the command using the provided `Dockerfile`
      ```
      docker build -t <your-docker-hub-username>/kube-proxy-rap:v1.21.10 .
      ```
      > You need to run this command at the location where both `Dockerfile` and built `kube-proxy` are present. Take a look at the Dockerfile for better understanding.
    - push the new docker image to the hub so that later it can be pulled by our k8s cluster
      ```
      docker push  <your-docker-hub-username>/kube-proxy-rap:v1.21.10
      ```
  - Now replace the image of `kube-proxy` that is being used by the daemon sets created by kubeadm
    ```
    kubectl edit daemonset kube-proxy -n kube-system
    kubectl rollout restart daemonset kube-proxy -n kube-system
    ```
  - Now this will spin up our new kube-proxy with rap enabled, and make sure that `userspace` mode is enabled. Refer to [this](https://stackoverflow.com/a/56497675) to know how to change it.
    
