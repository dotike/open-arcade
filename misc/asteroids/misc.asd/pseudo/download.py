def download(obj):

    try:
        client.download_file(Key=obj, Filename=obj, Bucket='asd2021')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("The object does not exist.")
        else:
            raise