Amazon EFS CSI driver



To create an IAM OIDC identity provider for your cluster with the AWS Management Console
Open the Amazon EKS console at https://console.aws.amazon.com/eks/home#/clusters.

In the left pane, select Clusters, and then select the name of your cluster on the Clusters page.

In the Details section on the Overview tab, note the value of the OpenID Connect provider URL.

Open the IAM console at https://console.aws.amazon.com/iam/.

In the left navigation pane, choose Identity Providers under Access management. If a Provider is listed that matches the URL for your cluster, then you already have a provider for your cluster. If a provider isn't listed that matches the URL for your cluster, then you must create one.

To create a provider, choose Add provider.

For Provider type, select OpenID Connect.

For Provider URL, enter the OIDC provider URL for your cluster, and then choose Get thumbprint.

For Audience, enter sts.amazonaws.com and choose Add provider.


Creating an IAM role -- cluster name add && role name of user choice

export cluster_name=cluster
export role_name=AmazonEKS_EFS_CSI_DriverRole
eksctl create iamserviceaccount \
    --name efs-csi-controller-sa \
    --namespace kube-system \
    --cluster $cluster_name \
    --role-name $role_name \
    --role-only \
    --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy \
    --approve
TRUST_POLICY=$(aws iam get-role --role-name $role_name --query 'Role.AssumeRolePolicyDocument' | \
    sed -e 's/efs-csi-controller-sa/efs-csi-*/' -e 's/StringEquals/StringLike/')
aws iam update-assume-role-policy --role-name $role_name --policy-document "$TRUST_POLICY"


 eksctl create iamserviceaccount \     
>     --name efs-csi-controller-sa \    
>     --namespace kube-system \
>     --cluster $cluster_name \
>     --role-name $role_name \
>     --role-only \
>     --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy \
>     --approve

2024-03-07 01:09:22 [ℹ]  1 iamserviceaccount (kube-system/efs-csi-controller-sa) was included (based on the 
include/exclude rules)
2024-03-07 01:09:22 [!]  serviceaccounts in Kubernetes will not be created or modified, since the option --role-only is used
2024-03-07 01:09:22 [ℹ]  1 task: { create IAM role for serviceaccount "kube-system/efs-csi-controller-sa" } 
2024-03-07 01:09:22 [ℹ]  building iamserviceaccount stack "eksctl-cluster-01-addon-iamserviceaccount-kube-system-efs-csi-controller-sa"
2024-03-07 01:09:22 [ℹ]  deploying stack "eksctl-cluster-01-addon-iamserviceaccount-kube-system-efs-csi-controller-sa"
2024-03-07 01:09:22 [ℹ]  waiting for CloudFormation stack "eksctl-cluster-01-addon-iamserviceaccount-kube-system-efs-csi-controller-sa"
2024-03-07 01:09:53 [ℹ]  waiting for CloudFormation stack "eksctl-cluster-01-addon-iamserviceaccount-kube-system-efs-csi-controller-sa"

TRUST_POLICY=$(aws iam get-role --role-name $role_name --query 'Role.AssumeRolePolicyDocument' | \
    sed -e 's/efs-csi-controller-sa/efs-csi-*/' -e 's/StringEquals/StringLike/')

aws iam update-assume-role-policy --role-name $role_name --policy-document "$TRUST_POLICY"


Creating an add-on


eksctl utils describe-addon-versions --kubernetes-version 1.27 | grep AddonName

eksctl utils describe-addon-versions --kubernetes-version 1.27 | grep AddonName
                        "AddonName": "vpc-cni",
                        "AddonName": "upwind-security_upwind-operator",
                        "AddonName": "tetrate-io_istio-distro",
                        "AddonName": "stormforge_optimize-live",
                        "AddonName": "splunk_splunk-otel-collector-chart",
                        "AddonName": "solo-io_istio-distro",
                        "AddonName": "snapshot-controller",
                        "AddonName": "rafay-systems_rafay-operator",
                        "AddonName": "new-relic_kubernetes-operator",
                        "AddonName": "netapp_trident-operator",
                        "AddonName": "leaksignal_leakagent",
                        "AddonName": "kubecost_kubecost",
                        "AddonName": "kube-proxy",
                        "AddonName": "kong_konnect-ri",
                        "AddonName": "haproxy-technologies_kubernetes-ingress-ee",
                        "AddonName": "groundcover_agent",
                        "AddonName": "grafana-labs_kubernetes-monitoring",
                        "AddonName": "eks-pod-identity-agent",
                        "AddonName": "dynatrace_dynatrace-operator",
                        "AddonName": "datadog_operator",
                        "AddonName": "cribl_cribledge",
                        "AddonName": "coredns",
                        "AddonName": "calyptia_fluent-bit",
                        "AddonName": "aws-mountpoint-s3-csi-driver",
                        "AddonName": "aws-guardduty-agent",
                        "AddonName": "aws-efs-csi-driver", <------add_on_name---->
                        "AddonName": "aws-ebs-csi-driver",
                        "AddonName": "amazon-cloudwatch-observability",
                        "AddonName": "adot",
                        "AddonName": "accuknox_kubearmor",

#add on name version change
eksctl utils describe-addon-versions --kubernetes-version 1.27 --name aws-efs-csi-driver | grep AddonVersion

$ eksctl utils describe-addon-versions --kubernetes-version 1.27 --name aws-efs-csi-driver | grep AddonVersion
                        "AddonVersions": [
                                        "AddonVersion": "v1.7.5-eksbuild.2",
                                        "AddonVersion": "v1.7.5-eksbuild.1",
                                        "AddonVersion": "v1.7.4-eksbuild.1",
                                        "AddonVersion": "v1.7.3-eksbuild.1",
                                        "AddonVersion": "v1.7.2-eksbuild.1",
                                        "AddonVersion": "v1.7.1-eksbuild.1",
                                        "AddonVersion": "v1.7.0-eksbuild.1",
                                        "AddonVersion": "v1.5.9-eksbuild.1",
                                        "AddonVersion": "v1.5.8-eksbuild.1",

eksctl utils describe-addon-versions --kubernetes-version 1.27 --name aws-efs-csi-driver | grep ProductUrl

eksctl create addon --cluster cluster --name aws-efs-csi-driver --version latest 

$ eksctl create addon --cluster cluster-01 --name aws-efs-csi-driver --version latest
2024-03-07 01:24:41 [ℹ]  Kubernetes version "1.27" in use by cluster "cluster-01"
2024-03-07 01:24:41 [ℹ]  creating role using recommended policies
2024-03-07 01:24:41 [ℹ]  deploying stack "eksctl-cluster-01-addon-aws-efs-csi-driver"
2024-03-07 01:24:41 [ℹ]  waiting for CloudFormation stack "eksctl-cluster-01-addon-aws-efs-csi-driver"
2024-03-07 01:25:12 [ℹ]  waiting for CloudFormation stack "eksctl-cluster-01-addon-aws-efs-csi-driver"
2024-03-07 01:25:59 [ℹ]  waiting for CloudFormation stack "eksctl-cluster-01-addon-aws-efs-csi-driver"
2024-03-07 01:25:59 [ℹ]  creating addon

eksctl create addon --help
#Check on eks cluster add on 

eksctl get addon --cluster cluster

$ eksctl get addon --cluster cluster
2024-03-07 01:27:44 [ℹ]  Kubernetes version "1.27" in use by cluster "cluster-01"
2024-03-07 01:27:44 [ℹ]  getting all addons
2024-03-07 01:27:45 [ℹ]  to see issues for an addon run `eksctl get addon --name <addon-name> --cluster <cluster-name>`
NAME                    VERSION                 STATUS  ISSUES  IAMROLE
                                        UPDATE AVAILABLE        CONFIGURATION VALUES
aws-efs-csi-driver      v1.7.5-eksbuild.2       ACTIVE  0       arn:aws:iam::073464498496:role/eksctl-cluster-01-addon-aws-efs-csi-driver-Role1-ArmLDJ1REueG


Create an Amazon EFS file system for Amazon EKS

To create an Amazon EFS file system for your Amazon EKS cluster

Retrieve the VPC ID that your cluster is in and store it in a variable for use in a later step. Replace my-cluster with your cluster name.

vpc_id=$(aws eks describe-cluster \
    --name cluster \
    --query "cluster.resourcesVpcConfig.vpcId" \
    --output text)

Retrieve the CIDR range for your cluster's VPC and store it in a variable for use in a later step. Replace region-code with the AWS Region that your cluster is in.

cidr_range=$(aws ec2 describe-vpcs \
    --vpc-ids $vpc_id \
    --query "Vpcs[].CidrBlock" \
    --output text \
    --region ap-south-1)


Create a security group with an inbound rule that allows inbound NFS traffic for your Amazon EFS mount points.

Create a security group. Replace the example values with your own.

security_group_id=$(aws ec2 create-security-group \
    --group-name MyEfsSecurityGroup \
    --description "My EFS security group" \
    --vpc-id $vpc_id \
    --output text)


Create an inbound rule that allows inbound NFS traffic from the CIDR for your cluster's VPC.

aws ec2 authorize-security-group-ingress \
    --group-id $security_group_id \
    --protocol tcp \
    --port 2049 \
    --cidr $cidr_range

Output
$ aws ec2 authorize-security-group-ingress \
>     --group-id $security_group_id \
>     --protocol tcp \
>     --port 2049 \
>     --cidr $cidr_range
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0dea0cdcd95915402",
            "GroupId": "sg-084bbbbe31338ea33",
            "GroupOwnerId": "073464498496",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 2049,
            "ToPort": 2049,
            "CidrIpv4": "192.168.0.0/16"
        }
    ]
}    

Important
To further restrict access to your file system, you can use the CIDR for your subnet instead of the VPC.

Create an Amazon EFS file system for your Amazon EKS cluster.

Create a file system. Replace region-code with the AWS Region that your cluster is in.

file_system_id=$(aws efs create-file-system \
    --region ap-south-1 \
    --performance-mode generalPurpose \
    --query 'FileSystemId' \
    --output text)

Create mount targets.

Determine the IP address of your cluster nodes.

kubectl get nodes

The example output is as follows.

NAME                                         STATUS   ROLES    AGE   VERSION
ip-192-168-56-0.region-code.compute.internal   Ready    <none>   19m   v1.XX.X-eks-49a6c0
Determine the IDs of the subnets in your VPC and which Availability Zone the subnet is in.

aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$vpc_id" \
    --query 'Subnets[*].{SubnetId: SubnetId,AvailabilityZone: AvailabilityZone,CidrBlock: CidrBlock}' \
    --output table

The example output is as follows.

|                           DescribeSubnets                          |
+------------------+--------------------+----------------------------+
| AvailabilityZone |     CidrBlock      |         SubnetId           |
+------------------+--------------------+----------------------------+
|  region-codec    |  192.168.128.0/19  |  subnet-EXAMPLE6e421a0e97  |
|  region-codeb    |  192.168.96.0/19   |  subnet-EXAMPLEd0503db0ec  |
|  region-codec    |  192.168.32.0/19   |  subnet-EXAMPLEe2ba886490  |
|  region-codeb    |  192.168.0.0/19    |  subnet-EXAMPLE123c7c5182  |
|  region-codea    |  192.168.160.0/19  |  subnet-EXAMPLE0416ce588p  |
+------------------+--------------------+----------------------------+
Add mount targets for the subnets that your nodes are in. From the output in the previous two steps, the cluster has one node with an IP address of 192.168.56.0. That IP address is within the CidrBlock of the subnet with the ID subnet-EXAMPLEe2ba886490. As a result, the following command creates a mount target for the subnet the node is in. If there were more nodes in the cluster, you'd run the command once for a subnet in each AZ that you had a node in, replacing subnet-EXAMPLEe2ba886490 with the appropriate subnet ID.


aws efs create-mount-target \
    --file-system-id $file_system_id \
    --subnet-id subnet-0c0776ee924ee800e \
    --security-groups $security_group_id

output

$ aws efs create-mount-target \
>     --file-system-id $file_system_id \
>     --subnet-id subnet-0c0776ee924ee800e \
>     --security-groups $security_group_id
{
    "OwnerId": "073464498496",
    "MountTargetId": "fsmt-0d26ef42bf1bb6c47",
    "FileSystemId": "fs-02b39d6c57bb8ff08",
    "SubnetId": "subnet-0c56f6985ef072016",
    "LifeCycleState": "creating",
    "IpAddress": "192.168.60.251",
    "NetworkInterfaceId": "eni-0aa135ea6a44c17f5",
    "AvailabilityZoneId": "aps1-az3",
    "AvailabilityZoneName": "ap-south-1b",
    "VpcId": "vpc-0b33a437dec41fd35"
}


Replace VolumeHandle value with FileSystemId of the EFS filesystem that needs to be mounted.

aws efs describe-file-systems --query "FileSystems[*].FileSystemId"
[
    "fs-02b39d6c57bb8ff08",
    "fs-0cef07b001afbdc62"
]

kubectl logs efs-csi-controller-5c8cd69486-7c2gh \
    -n kube-system \
    -c csi-provisioner \
    --tail 10


Dynamic Provisioning
Important
You can't use dynamic provisioning with Fargate nodes.

This example shows how to create a dynamically provisioned volume created through Amazon EFS access points and a persistent volume claim (PVC) that's consumed by a Pod.

Prerequisite
This example requires Kubernetes 1.17 or later and a driver version of 1.2.0 or later.

Create a storage class for Amazon EFS.

Retrieve your Amazon EFS file system ID. You can find this in the Amazon EFS console, or use the following AWS CLI command.

aws efs describe-file-systems --query "FileSystems[*].FileSystemId" --output text
The example output is as follows.

fs-582a03f3
Download a StorageClass manifest for Amazon EFS.

curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-efs-csi-driver/master/examples/kubernetes/dynamic_provisioning/specs/storageclass.yaml
Edit the file. Find the following line, and replace the value for fileSystemId with your file system ID.

fileSystemId: fs-582a03f3
Modify the other values as needed:

provisioningMode - The type of volume to be provisioned by Amazon EFS. Currently, only access point based provisioning is supported (efs-ap).
fileSystemId - The file system under which the access point is created.
directoryPerms - The directory permissions of the root directory created by the access point.
gidRangeStart (Optional) - The starting range of the Posix group ID to be applied onto the root directory of the access point. The default value is 50000.
gidRangeEnd (Optional) - The ending range of the Posix group ID. The default value is 7000000.
basePath (Optional) - The path on the file system under which the access point root directory is created. If the path isn't provided, the access points root directory is created under the root of the file system.
subPathPattern (Optional) - A pattern that describes the subPath under which an access point should be created. So if the pattern were ${.PVC.namespace}/${PVC.name}, the PVC namespace is foo and the PVC name is pvc-123-456, and the basePath is /dynamic_provisioner the access point would be created at /dynamic_provisioner/foo/pvc-123-456.
ensureUniqueDirectory (Optional) - A boolean that ensures that, if set, a UUID is appended to the final element of any dynamically provisioned path, as in the above example. This can be turned off but this requires you as the administrator to ensure that your storage classes are set up correctly. Otherwise, it's possible that 2 pods could end up writing to the same directory by accident. Please think very carefully before setting this to false!
Deploy the storage class.

kubectl apply -f storageclass.yaml
Test automatic provisioning by deploying a Pod that makes use of the PVC:

Download a manifest that deploys a Pod and a PVC.

curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-efs-csi-driver/master/examples/kubernetes/dynamic_provisioning/specs/pod.yaml
Deploy the Pod with a sample app and the PVC used by the Pod.

kubectl apply -f pod.yaml
Determine the names of the Pods running the controller.

kubectl get pods -n kube-system | grep efs-csi-controller
The example output is as follows.

efs-csi-controller-74ccf9f566-q5989   3/3     Running   0          40m
efs-csi-controller-74ccf9f566-wswg9   3/3     Running   0          40m
After few seconds, you can observe the controller picking up the change (edited for readability). Replace 74ccf9f566-q5989 with a value from one of the Pods in your output from the previous command.

kubectl logs efs-csi-controller-74ccf9f566-q5989 \
    -n kube-system \
    -c csi-provisioner \
    --tail 10
The example output is as follows.

[...]
1 controller.go:737] successfully created PV pvc-5983ffec-96cf-40c1-9cd6-e5686ca84eca for PVC efs-claim and csi volume name fs-95bcec92::fsap-02a88145b865d3a87
If you don't see the previous output, run the previous command using one of the other controller Pods.

Confirm that a persistent volume was created with a status of Bound to a PersistentVolumeClaim:

kubectl get pv
The example output is as follows.

NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM               STORAGECLASS   REASON   AGE
pvc-5983ffec-96cf-40c1-9cd6-e5686ca84eca   20Gi       RWX            Delete           Bound    default/efs-claim   efs-sc                  7m57s
View details about the PersistentVolumeClaim that was created.

kubectl get pvc
The example output is as follows.

NAME        STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
efs-claim   Bound    pvc-5983ffec-96cf-40c1-9cd6-e5686ca84eca   20Gi       RWX            efs-sc         9m7s
View the sample app Pod's status until the STATUS becomes Running.

kubectl get pods -o wide
The example output is as follows.

NAME          READY   STATUS    RESTARTS   AGE   IP               NODE                                             NOMINATED NODE   READINESS GATES
efs-app       1/1     Running   0          10m   192.168.78.156   ip-192-168-73-191.region-code.compute.internal   <none>           <none>
Note
If a Pod doesn't have an IP address listed, make sure that you added a mount target for the subnet that your node is in (as described at the end of Create an Amazon EFS file system). Otherwise the Pod won't leave ContainerCreating status. When an IP address is listed, it may take a few minutes for a Pod to reach the Running status.

Confirm that the data is written to the volume.

kubectl exec efs-app -- bash -c "cat data/out"
The example output is as follows.

[...]
Tue Mar 23 14:29:16 UTC 2021
Tue Mar 23 14:29:21 UTC 2021
Tue Mar 23 14:29:26 UTC 2021
Tue Mar 23 14:29:31 UTC 2021
[...]
(Optional) Terminate the Amazon EKS node that your Pod is running on and wait for the Pod to be re-scheduled. Alternately, you can delete the Pod and redeploy it. Complete the previous step again, confirming that the output includes the previous output.

Note
When you want to delete an access point in a file system when deleting PVC, you should specify elasticfilesystem:ClientRootAccess to the file system access policy to provide the root permissions.
