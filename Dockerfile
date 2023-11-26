# Start from a base image that includes the necessary dependencies
FROM k8s.gcr.io/kube-proxy:v1.21.10

# Copy the new kube-proxy binary into the image
COPY kube-proxy /usr/local/bin/kube-proxy

# Set any additional configurations or environment variables
# ...

# Define the command to run when the container starts
CMD ["/usr/local/bin/kube-proxy"]
