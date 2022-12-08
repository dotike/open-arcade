# Frontend Code

## How to run the placeholder locally

`cd static`

`python -m http.server 5000`

Then just visit http://localhost:5000 in your browser. This is handy for local development.

## First time setup on an asteroid

Note: After you have a running asteroid, you should be able to just update configs in secretesmanager and restart the asteroid as needed (see below)

Step 1: Upload the asd file to S3

`arcade asd upload -f demo-aarf.json`

Step 2: Create a new asteroid and add the asd file to it (TBC; see main docs)

Step 3: Upload the configuration files to secrets managers. TODO: script this

- Begin by creating a secret of the form `<arcade_name>/<asteroid_name>/<service_name>/configs/`
- Upload configs.json to the secrets store (the keys indicate the filename and where narc reconcile will put them, the values are the base64-encoded contents)

Step 4: Enable the asteroid and reconcile

Step 5: Connect

- `arcade config kubectl -A ${ARCADE_NAME}`
- `k get pods -n $ASTEROID_NAME`
- `sudo kubectl port-forward pod/<pod_name_from_above> 80:5000 -n ${ASTEROID_NAME}`
- http://127.0.0.1


## Updating Configs in Secrets Manager

Let's say you changed the index.html page. First, encode your new file:

`base64 -i index.html`

Now copy and paste the output of the above command into the appropiate secretsmanager config section. 

TODO: add a helper script to push all the configs from the command line

Now just reconcile the changes:

`arcade narc reconcile`

Optional: If you want to be a good person, also copy your changes to configs.json
