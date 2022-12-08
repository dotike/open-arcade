# ARCADE Development: Common operations

### This is a document that provides detailed steps about how to perform common operations on Arcades.

### Please add new sections when available!

## Check your Arcade related environment variables.
  > % env | sort | grep -iE 'arcade|asteroid|aws|bucket'

## How to delete an arcade, even when it is broken.

- Make sure it actually exists.
  >`% arcade list | grep ${ARCADE_NAME}`

- Shut down any currently running asteroids.
  > `% arcade asteroid list -A ${ARCADE_NAME}`
  >
  > `% arcade asteroid disable -A ${ARCADE_NAME} -a ${ASTEROID_NAME}`
  >
  > `% arcade narc reconcile`
  - Repeat until all arcades have stopped.

- Find arcade related files in S3.
  > `% arcade galaga find -A ${ARCADE_NAME} --galaga`
  >
  > `% arcade galaga list`
  >
  > `% arcade galaga destroy -A ${ARCADE_NAME} -p <derived from the above?>`
  - if that fails:
  > `% arcade galaga destroy -A ${ARCADE_NAME} -p galaga/aoax/default.json`
  - and if that fails:
    - Delete node group.
      - Go to EKS / Clusters / \<filter\> / select / Compute / select node group / Delete
      - Wait for it to disappear. (8 - 9 minutes before it says it is gone. Maybe 24 hours before it really is!)
      - When the node group is deleted, go back to Configuration and Delete cluster
      - Then delete cluster (2 - 25 minutes)

- Delete the gravatar layer.
  > `% arcade grv destroy -y -A ${ARCADE_NAME} -3`
  - (maybe 10 minutes)
  - If that succeeds, delete the VPC:
    - VPC / Your VPCs / \<filter\> / Select / Actions / Delete VPC

- delete listeners; delete albs (load balancers)
  - EC2 / Load Balancers / \<filter\> / Select (private and public) then Actions/Delete

- Terminate instances:
  - EC2 / Instances / \<filter\> / Select all related to your arcade / Instance state / Terminate instance
    ( This may take quite a while or sometimes not very long. )

- Delete Auto Scaling group:
  - EC2 / Auto Scaling groups / \<filter\> / Select / Delete

- Check for RDS Databases.
  - Go to RDS / Databases / \<filter\> / Select / Action / Delete / "delete me"
  - This may take a while...

- Check for MSK Clusters.
  - Go to MSK / Clusters / \<filter\> / Select / Actions / Delete
    - This one auto refreshes!
    - This too may take a while...

- Now delete the VPC:
  - VPC / Your VPCs / \<filter\> / Select / Actions / Delete VPC

  - If the VPC can't be deleted, check the Network Interface. You can get there directly from the
    "Delete VPC" Popup that says you can't delete the VPC.
    Filter to your arcade name and select it. Click on the Network interface name "eni-####".
    Go to ElastiCache and find your cache. The name of it is provided in the details of the Network
    interface above. Delete the cache. You might need to delete some nodes first. Start from high
    numbers and work your way down.
    When done try to delete the VPC again.

- Delete the routes:
  - Always check Route 53 as sometimes even a clean delete of an arcade may leave something here!
  - Route 53 / Hosted Zones / Click on "info.arc" / \<filter\> / ( Don't select \<XXXXXXX.grvname.info.arc\> &nbsp; Do select \<used.XXXXXXX.grv{name,net}.info.arc\> ) / Delete records

- Check for completion:
  > `% arcade list | grep ${ARCADE_NAME}`

## How to re/build a docker container for an asteroid.

- Determine the container store on AWS where it lives.
  - Find the ASD file that uses that container.
  - Under "containers" / "image" you will find the AWS region and the name of the continer.
  - Go to the Amazon ECR / Repositories web page in the AWS region found above.
  - Click on the name of your image.
  - Click on "View push commands".
  - Click on the "copy" icon at the left end of each of the commands.
  - In a shell "cd" to the image directory for your container.
  - Paste the commands one at a time into your shell.
  - For the "docker build" command you may need to add the args "--platform linux/x86_64".
  - Be sure to run all the commands in order.
  - Your image should be available now on all AWS regions.
