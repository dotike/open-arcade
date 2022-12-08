# Galaga module

## Prometheus Grafana

### Description
This installer will create the component infrastructure necessary for Prometheus/Grafana to run on EKS. This will set up the following:

* AWS Managed Grafana
* AWS Managed Prometheus
* Prometheus installed on EKS cluster
  * This will talk to AWS Managed Promethues
* Sets up OICD provider and permissions for EKS

### How to Configure and run:

* Upload GSD
  * `arcade gsd upload -f /Users/someuser/prometheus/libexec/galaga-modules/prometheus/prometheus.json`
  * This will upload the gsd to the asd bucket

```json
{
    "name": "prometheus",
    "component_type": "prometheus",
    "version": 2,
    "description": "GSD for prometheus",
    "services": {
      "prometheus": {
        "service_options": {}
      }
    }
  }
```

* Create Galaga Service Definition File for `arcade galaga create`
  * Add Prometheus
  * `arcade galaga setup -C -p gsd/prometheus/latest/latest.json`
  * Add EKS, EKS is a must for prometheus to work
  * `arcade galaga setup -p gsd/asteroids-eks/latest/latest.json`

```json
{
    "user": "some.user",
    "createTime": "2022/08/31/20/38",
    "name": "bad_neon.arc",
    "version": 1,
    "components": {
        "prometheus": {
            "location": "gsd/prometheus/latest/latest.json",
            "overrides": {}
        },
        "asteroids-eks": {
            "location": "gsd/asteroids-eks/latest/latest.json",
            "overrides": {}
        }
    }
}

```

* Now we are ready to upload the Galaga Service Definition File
  * `arcade galaga upload -f /Users/someuser/tmp/arcade/bad_neon.arc.json`

* Finally run `arcade galaga create`

`arcade galaga create -p galaga/bad_neon.arc/latest/latest.json`



### Note: If prometheus fails then try running it again. Sometimes the EKS cluster is not ready. 