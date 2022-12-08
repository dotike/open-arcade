import boto3

client = boto3.client('s3')
bucket_name = "asd2021"
prefix = ""

s3 = boto3.client("s3")

def ListFiles(client, bucket_name, prefix):
    BucketName = bucket_name
    PrefixName = prefix
    response = client.list_objects(Bucket=BucketName, Prefix=PrefixName)

    for content in response.get('Contents', []):
        yield content.get('Key')

result = client.list_objects(Bucket=bucket_name, Delimiter='/')
for obj in result.get('CommonPrefixes'):  
   prefix = obj.get('Prefix')
   file_list = ListFiles(client,bucket_name,prefix)
   for file in file_list:
          print("Found:",file)