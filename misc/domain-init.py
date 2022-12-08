import boto3
import botocore.exceptions

def listHostedZones():
	client = boto3.client('route53')
	response = client.list_hosted_zones(
    MaxItems='100',
	)

def getHostedZone(hostedZoneName):
	client = boto3.client('route53')
	response = client.get_hosted_zone(
	    Id=hostedZoneName
	)

def createHostedZone(hostedZoneName):
	client = boto3.client('route53')
	response = client.create_hosted_zone(
	    Name=hostedZoneName,
	    CallerReference=hostedZoneName,
	    HostedZoneConfig={
	        'Comment': 'Account Super Hosted Zone',
	        'PrivateZone': False
	    },
	)

def main():
	print("Please enter domain name for account. i.e: coneydevcloud.com")
	hostedZoneName = input("---> ")
	try:
		createHostedZone(hostedZoneName)
		print(" Hosted Zone for: " + hostedZoneName + " has been created.")
	except botocore.exceptions.ClientError as error:
		raise error

if __name__ == '__main__':
    main()