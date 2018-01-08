metadata:
  creationTimestamp: 2017-12-19T14:52:42Z
  name: ${CLUSTER}
spec:
#  egressProxy:
#    httpProxy:
#      host: proxy.service.consul
#      port: 3128
#    excludes: localhost,127.0.0.1,.localdomain,.service.consul,service.consul,.consul,consul,169.254.169.254,100.64.
  api:
    loadBalancer:
      type: Internal
  authorization:
    rbac: {}
  channel: stable
  cloudProvider: aws
  clusterDNSDomain: cluster.local
  configBase: s3://${BUCKET}
  configStore: s3://${BUCKET}
  dnsZone: ${ZONE_ID}
  docker:
    bridge: ""
    ipMasq: false
    ipTables: false
    logDriver: json-file
    logLevel: warn
    logOpt:
    - max-size=10m
    - max-file=5
    storage: overlay,aufs
    version: 1.13.1
  etcdClusters:
  - etcdMembers:
    - encryptedVolume: true
      instanceGroup: master-${element(split(",",AVAILABILITY_ZONES), 0)}
      name: "1"
    - encryptedVolume: true
      instanceGroup: master-${element(split(",",AVAILABILITY_ZONES), 1)}
      name: "2"
    - encryptedVolume: true
      instanceGroup: master-${element(split(",",AVAILABILITY_ZONES), 2)}
      name: "3"
    name: main
    version: 2.2.1
  - etcdMembers:
    - encryptedVolume: true
      instanceGroup: master-${element(split(",",AVAILABILITY_ZONES), 0)}
      name: "1"
    - encryptedVolume: true
      instanceGroup: master-${element(split(",",AVAILABILITY_ZONES), 1)}
      name: "2"
    - encryptedVolume: true
      instanceGroup: master-${element(split(",",AVAILABILITY_ZONES), 2)}
      name: "3"
    name: events
    version: 2.2.1
  iam:
    allowContainerRegistry: true
    legacy: false
  keyStore: s3://${BUCKET}/pki
  kubeAPIServer:
    address: 127.0.0.1
    admissionControl:
    - Initializers
    - NamespaceLifecycle
    - LimitRanger
    - ServiceAccount
    - PersistentVolumeLabel
    - DefaultStorageClass
    - DefaultTolerationSeconds
    - NodeRestriction
    - Priority
    - ResourceQuota
    allowPrivileged: true
    anonymousAuth: false
    apiServerCount: 3
    authorizationMode: RBAC
    cloudProvider: aws
    etcdServers:
    - http://127.0.0.1:4001
    etcdServersOverrides:
    - /events#http://127.0.0.1:4002
    image: gcr.io/google_containers/kube-apiserver:v1.8.4
    insecurePort: 8080
    kubeletPreferredAddressTypes:
    - InternalIP
    - Hostname
    - ExternalIP
    logLevel: 2
    requestheaderAllowedNames:
    - aggregator
    requestheaderExtraHeaderPrefixes:
    - X-Remote-Extra-
    requestheaderGroupHeaders:
    - X-Remote-Group
    requestheaderUsernameHeaders:
    - X-Remote-User
    securePort: 443
    serviceClusterIPRange: 100.64.0.0/13
    storageBackend: etcd2
  kubeControllerManager:
    allocateNodeCIDRs: true
    attachDetachReconcileSyncPeriod: 1m0s
    cloudProvider: aws
    clusterCIDR: 100.96.0.0/11
    clusterName: ${CLUSTER}
    configureCloudRoutes: false
    image: gcr.io/google_containers/kube-controller-manager:v1.8.4
    leaderElection:
      leaderElect: true
    logLevel: 2
    useServiceAccountCredentials: true
  kubeDNS:
    domain: cluster.local
    replicas: 2
    serverIP: 100.64.0.10
  kubeProxy:
    clusterCIDR: 100.96.0.0/11
    cpuRequest: 100m
    featureGates: null
    hostnameOverride: '@aws'
    image: gcr.io/google_containers/kube-proxy:v1.8.4
    logLevel: 2
  kubeScheduler:
    image: gcr.io/google_containers/kube-scheduler:v1.8.4
    leaderElection:
      leaderElect: true
    logLevel: 2
  kubelet:
    allowPrivileged: true
    cgroupRoot: /
    cloudProvider: aws
    clusterDNS: 100.64.0.10
    clusterDomain: cluster.local
    enableDebuggingHandlers: true
    evictionHard: memory.available<100Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<10%,imagefs.inodesFree<5%
    featureGates:
      ExperimentalCriticalPodAnnotation: "true"
    hostnameOverride: '@aws'
    kubeconfigPath: /var/lib/kubelet/kubeconfig
    logLevel: 2
    networkPluginName: cni
    nonMasqueradeCIDR: 100.64.0.0/10
    podInfraContainerImage: gcr.io/google_containers/pause-amd64:3.0
    podManifestPath: /etc/kubernetes/manifests
    requireKubeconfig: true
  kubernetesApiAccess:
  - 0.0.0.0/0
  kubernetesVersion: 1.8.4
  masterInternalName: api.internal.${CLUSTER}
  masterKubelet:
    allowPrivileged: true
    cgroupRoot: /
    cloudProvider: aws
    clusterDNS: 100.64.0.10
    clusterDomain: cluster.local
    enableDebuggingHandlers: true
    evictionHard: memory.available<100Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<10%,imagefs.inodesFree<5%
    featureGates:
      ExperimentalCriticalPodAnnotation: "true"
    hostnameOverride: '@aws'
    kubeconfigPath: /var/lib/kubelet/kubeconfig
    logLevel: 2
    networkPluginName: cni
    nonMasqueradeCIDR: 100.64.0.0/10
    podInfraContainerImage: gcr.io/google_containers/pause-amd64:3.0
    podManifestPath: /etc/kubernetes/manifests
    registerSchedulable: false
    requireKubeconfig: true
  masterPublicName: api.${CLUSTER}
  networkCIDR: ${NETWORK_CIDR}
  networking:
    calico: {}
  nonMasqueradeCIDR: 100.64.0.0/10
  secretStore: s3://${BUCKET}/secrets
  serviceClusterIPRange: 100.64.0.0/13
  sshAccess:
  - 0.0.0.0/0
  topology:
    dns:
      type: Public
    masters: private
    nodes: private
