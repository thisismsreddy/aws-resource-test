import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate

# We only want to check these two regions:
REGIONS = ["us-east-1", "us-west-1"]

def gather_ec2_data():
    """
    Gathers:
      - EC2 instances (running/stopped)
      - Unattached EBS volumes
      - NAT Gateways
      - Internet Gateways
      - Elastic IP addresses
    Returns them as lists of dicts (one for each table).
    """
    ec2_instances_data = []
    ec2_volumes_data = []
    nat_gateways_data = []
    internet_gateways_data = []
    elastic_ips_data = []

    for region in REGIONS:
        ec2 = boto3.client('ec2', region_name=region)

        # 1) EC2 Instances
        try:
            reservations = ec2.describe_instances()['Reservations']
            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId')
                    state = instance['State']['Name']
                    ec2_instances_data.append({
                        "Region": region,
                        "InstanceId": instance_id,
                        "State": state
                    })
        except ClientError as e:
            print(f"Error describing instances in {region}: {e}")

        # 2) Unattached EBS Volumes
        try:
            volumes = ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )['Volumes']
            for vol in volumes:
                ec2_volumes_data.append({
                    "Region": region,
                    "VolumeId": vol['VolumeId'],
                    "Size (GiB)": vol['Size']
                })
        except ClientError as e:
            print(f"Error describing volumes in {region}: {e}")

        # 3) NAT Gateways
        try:
            response = ec2.describe_nat_gateways()
            nat_gws = response.get('NatGateways', [])
            for ngw in nat_gws:
                nat_gateways_data.append({
                    "Region": region,
                    "NatGatewayId": ngw['NatGatewayId'],
                    "State": ngw['State'],
                    "VpcId": ngw['VpcId']
                })
        except ClientError as e:
            print(f"Error describing NAT Gateways in {region}: {e}")

        # 4) Internet Gateways
        try:
            response = ec2.describe_internet_gateways()
            igws = response.get('InternetGateways', [])
            for igw in igws:
                igw_id = igw['InternetGatewayId']
                attachments = igw.get('Attachments', [])
                # Collect the attached VPC IDs (usually zero or one).
                attached_vpcs = [att['VpcId'] for att in attachments if 'VpcId' in att]
                internet_gateways_data.append({
                    "Region": region,
                    "InternetGatewayId": igw_id,
                    "AttachedVPCs": ", ".join(attached_vpcs) if attached_vpcs else "None"
                })
        except ClientError as e:
            print(f"Error describing Internet Gateways in {region}: {e}")

        # 5) Elastic IPs
        try:
            response = ec2.describe_addresses()
            addresses = response.get('Addresses', [])
            for addr in addresses:
                public_ip = addr.get('PublicIp')
                allocation_id = addr.get('AllocationId')
                instance_id = addr.get('InstanceId')
                network_interface_id = addr.get('NetworkInterfaceId')
                elastic_ips_data.append({
                    "Region": region,
                    "PublicIp": public_ip,
                    "AllocationId": allocation_id if allocation_id else "N/A",
                    "InstanceId": instance_id if instance_id else "N/A",
                    "NetworkInterfaceId": network_interface_id if network_interface_id else "N/A"
                })
        except ClientError as e:
            print(f"Error describing Elastic IPs in {region}: {e}")

    return (ec2_instances_data,
            ec2_volumes_data,
            nat_gateways_data,
            internet_gateways_data,
            elastic_ips_data)


def gather_s3_data():
    """
    Lists all S3 buckets (S3 is global).
    Returns a list of dicts.
    """
    s3_data = []
    s3 = boto3.client('s3')
    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        for b in buckets:
            s3_data.append({
                "BucketName": b['Name'],
                "CreationDate": str(b['CreationDate'])
            })
    except ClientError as e:
        print(f"Error listing S3 buckets: {e}")

    return s3_data


def gather_rds_data():
    """
    Lists RDS DB instances in the specified regions.
    Returns a list of dicts.
    """
    rds_data = []
    for region in REGIONS:
        rds = boto3.client('rds', region_name=region)
        try:
            response = rds.describe_db_instances()
            db_instances = response.get('DBInstances', [])
            for db_instance in db_instances:
                identifier = db_instance['DBInstanceIdentifier']
                status = db_instance['DBInstanceStatus']
                engine = db_instance['Engine']
                rds_data.append({
                    "Region": region,
                    "DBInstanceIdentifier": identifier,
                    "Status": status,
                    "Engine": engine
                })
        except ClientError as e:
            print(f"Error describing RDS instances in {region}: {e}")
    return rds_data


def gather_ecs_data():
    """
    Lists ECS clusters and their services in the specified regions.
    Returns a list of dicts.
    """
    ecs_data = []
    for region in REGIONS:
        ecs = boto3.client('ecs', region_name=region)
        try:
            clusters_arns = ecs.list_clusters()['clusterArns']
            for cluster_arn in clusters_arns:
                services_arns = ecs.list_services(cluster=cluster_arn)['serviceArns']
                if services_arns:
                    service_desc = ecs.describe_services(cluster=cluster_arn, services=services_arns)
                    for svc in service_desc['services']:
                        ecs_data.append({
                            "Region": region,
                            "ClusterArn": cluster_arn,
                            "ServiceName": svc['serviceName'],
                            "Status": svc['status']
                        })
                else:
                    # Even if there are no services, show the cluster
                    ecs_data.append({
                        "Region": region,
                        "ClusterArn": cluster_arn,
                        "ServiceName": "No Services",
                        "Status": "N/A"
                    })
        except ClientError as e:
            print(f"Error describing ECS in {region}: {e}")
    return ecs_data


def gather_eks_data():
    """
    Lists EKS clusters in the specified regions.
    Returns a list of dicts.
    """
    eks_data = []
    for region in REGIONS:
        eks = boto3.client('eks', region_name=region)
        try:
            cluster_list = eks.list_clusters()['clusters']
            for cluster_name in cluster_list:
                desc = eks.describe_cluster(name=cluster_name)
                status = desc['cluster']['status']
                version = desc['cluster']['version']
                eks_data.append({
                    "Region": region,
                    "ClusterName": cluster_name,
                    "Status": status,
                    "Version": version
                })
        except ClientError as e:
            print(f"Error describing EKS in {region}: {e}")
    return eks_data


def gather_lambda_data():
    """
    Lists AWS Lambda functions in the specified regions.
    Returns a list of dicts.
    """
    lambda_data = []
    for region in REGIONS:
        lam = boto3.client('lambda', region_name=region)
        try:
            paginator = lam.get_paginator('list_functions')
            for page in paginator.paginate():
                functions = page.get('Functions', [])
                for fn in functions:
                    lambda_data.append({
                        "Region": region,
                        "FunctionName": fn['FunctionName'],
                        "Runtime": fn['Runtime'],
                        "LastModified": fn['LastModified']
                    })
        except ClientError as e:
            print(f"Error listing Lambda functions in {region}: {e}")
    return lambda_data


def gather_elbv2_data():
    """
    Lists ALBs/NLBs (ELBv2) in the specified regions.
    Returns a list of dicts.
    """
    elbv2_data = []
    for region in REGIONS:
        elbv2 = boto3.client('elbv2', region_name=region)
        try:
            response = elbv2.describe_load_balancers()
            lbs = response.get('LoadBalancers', [])
            for lb in lbs:
                elbv2_data.append({
                    "Region": region,
                    "LoadBalancerName": lb.get('LoadBalancerName'),
                    "Type": lb.get('Type'),
                    "ARN": lb.get('LoadBalancerArn'),
                    "State": lb['State']['Code']
                })
        except ClientError as e:
            print(f"Error describing load balancers in {region}: {e}")
    return elbv2_data


def gather_apigw_data():
    """
    Lists API Gateway v1 (REST APIs) and v2 (HTTP/WebSocket APIs) in the specified regions.
    Returns two lists of dicts (for v1 and v2).
    """
    apigw_v1_data = []
    apigw_v2_data = []

    for region in REGIONS:
        # v1
        apig_v1 = boto3.client('apigateway', region_name=region)
        try:
            rest_apis = apig_v1.get_rest_apis().get('items', [])
            for api in rest_apis:
                apigw_v1_data.append({
                    "Region": region,
                    "APIName": api['name'],
                    "APIId": api['id'],
                    "Description": api.get('description', 'N/A')
                })
        except ClientError as e:
            print(f"Error describing API Gateway (v1) in {region}: {e}")

        # v2
        apig_v2 = boto3.client('apigatewayv2', region_name=region)
        try:
            v2_apis = apig_v2.get_apis().get('Items', [])
            for api in v2_apis:
                apigw_v2_data.append({
                    "Region": region,
                    "APIName": api.get('Name'),
                    "APIId": api.get('ApiId'),
                    "ProtocolType": api.get('ProtocolType')
                })
        except ClientError as e:
            print(f"Error describing API Gateway (v2) in {region}: {e}")

    return apigw_v1_data, apigw_v2_data

def gather_dynamodb_data():
    """
    Lists DynamoDB tables in the specified regions.
    Returns a list of dicts, each representing one table.
    """
    dynamodb_data = []
    for region in REGIONS:
        dynamodb = boto3.client('dynamodb', region_name=region)
        try:
            # Paginate through all tables in this region
            last_evaluated_table_name = None
            while True:
                if last_evaluated_table_name:
                    response = dynamodb.list_tables(ExclusiveStartTableName=last_evaluated_table_name)
                else:
                    response = dynamodb.list_tables()

                table_names = response.get('TableNames', [])
                for table_name in table_names:
                    # Describe the table to get more info
                    desc = dynamodb.describe_table(TableName=table_name)
                    table_desc = desc['Table']

                    table_info = {
                        "Region": region,
                        "TableName": table_desc['TableName'],
                        "Status": table_desc.get('TableStatus', 'N/A'),
                        "ItemCount": table_desc.get('ItemCount', 0),
                        "CreationDate": str(table_desc.get('CreationDateTime', 'N/A'))
                    }

                    # Optionally show billing mode (PROVISIONED or PAY_PER_REQUEST)
                    if 'BillingModeSummary' in table_desc:
                        table_info["BillingMode"] = table_desc['BillingModeSummary'].get('BillingMode', 'N/A')

                    dynamodb_data.append(table_info)

                # Check if there's another page of table names
                last_evaluated_table_name = response.get('LastEvaluatedTableName')
                if not last_evaluated_table_name:
                    break
        except ClientError as e:
            print(f"Error describing DynamoDB in {region}: {e}")

    return dynamodb_data


def main():
    # Gather EC2-related resources
    (ec2_instances_data,
     ec2_volumes_data,
     nat_gateways_data,
     internet_gateways_data,
     elastic_ips_data) = gather_ec2_data()

    # S3
    s3_data = gather_s3_data()

    # RDS
    rds_data = gather_rds_data()

    # ECS
    ecs_data = gather_ecs_data()

    # EKS
    eks_data = gather_eks_data()

    # Lambda
    lambda_data = gather_lambda_data()

    # ELBv2
    elbv2_data = gather_elbv2_data()

    # API Gateway
    apigw_v1_data, apigw_v2_data = gather_apigw_data()
    
     # Gather DynamoDB data
    dynamodb_data = gather_dynamodb_data()


    #
    # Now print tables using tabulate
    #
    print("\n=== EC2 Instances ===")
    if ec2_instances_data:
        print(tabulate(ec2_instances_data, headers="keys", tablefmt="github"))
    else:
        print("No EC2 instances found.")

    print("\n=== Unattached EBS Volumes ===")
    if ec2_volumes_data:
        print(tabulate(ec2_volumes_data, headers="keys", tablefmt="github"))
    else:
        print("No unattached EBS volumes found.")

    print("\n=== NAT Gateways ===")
    if nat_gateways_data:
        print(tabulate(nat_gateways_data, headers="keys", tablefmt="github"))
    else:
        print("No NAT Gateways found.")

    print("\n=== Internet Gateways ===")
    if internet_gateways_data:
        print(tabulate(internet_gateways_data, headers="keys", tablefmt="github"))
    else:
        print("No Internet Gateways found.")

    print("\n=== Elastic IP Addresses ===")
    if elastic_ips_data:
        print(tabulate(elastic_ips_data, headers="keys", tablefmt="github"))
    else:
        print("No Elastic IP addresses found.")

    print("\n=== S3 Buckets ===")
    if s3_data:
        print(tabulate(s3_data, headers="keys", tablefmt="github"))
    else:
        print("No S3 buckets found.")

    print("\n=== RDS Instances ===")
    if rds_data:
        print(tabulate(rds_data, headers="keys", tablefmt="github"))
    else:
        print("No RDS instances found.")

    print("\n=== ECS Clusters/Services ===")
    if ecs_data:
        print(tabulate(ecs_data, headers="keys", tablefmt="github"))
    else:
        print("No ECS clusters/services found.")

    print("\n=== EKS Clusters ===")
    if eks_data:
        print(tabulate(eks_data, headers="keys", tablefmt="github"))
    else:
        print("No EKS clusters found.")

    print("\n=== Lambda Functions ===")
    if lambda_data:
        print(tabulate(lambda_data, headers="keys", tablefmt="github"))
    else:
        print("No Lambda functions found.")

    print("\n=== ALB/NLB (ELBv2) ===")
    if elbv2_data:
        print(tabulate(elbv2_data, headers="keys", tablefmt="github"))
    else:
        print("No ALB/NLB found.")

    print("\n=== API Gateway (v1 REST) ===")
    if apigw_v1_data:
        print(tabulate(apigw_v1_data, headers="keys", tablefmt="github"))
    else:
        print("No REST APIs found.")

    print("\n=== API Gateway (v2 HTTP/WebSocket) ===")
    if apigw_v2_data:
        print(tabulate(apigw_v2_data, headers="keys", tablefmt="github"))
    else:
        print("No HTTP/WebSocket APIs found.")

    print("\nFinished checking AWS resources in us-east-1 and us-west-1.\n")
    
    print("\n=== DynamoDB Tables ===")
    if dynamodb_data:
        print(tabulate(dynamodb_data, headers="keys", tablefmt="github"))
    else:
        print("No DynamoDB tables found.")
    
    print("\nFinished checking AWS resources in us-east-1 and us-west-1.\n")



if __name__ == "__main__":
    main()
