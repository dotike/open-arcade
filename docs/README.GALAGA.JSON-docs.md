# Common GALAGA JSON document operations

### Find Galaga JSON files to work on.

`% arcade galaga find --galaga`

```
galaga-schema.json
galaga/aoa-dev/1/2022/05/04/16/08/96256a87b888709447bbc32164e9b6fb.json
galaga/aoax/2/2022/05/18/18/52/0fded0e5e65b2beb35ef11e525ae2246.json
galaga/aoax/default.json
galaga/aoax/latest/latest.json
galaga/asteroids/1/2022/05/02/16/00/27ef0297203219751d0a8f671d5e3aba.json
galaga/asteroids/1/2022/05/02/16/40/27ef0297203219751d0a8f671d5e3aba.json
galaga/asteroids/1/2022/05/02/16/43/27ef0297203219751d0a8f671d5e3aba.json
galaga/asteroids/1/2022/05/18/18/50/27ef0297203219751d0a8f671d5e3aba.json
galaga/asteroids/1/2022/06/03/19/03/3c2eef93a8488df7b6930d7269814312.json
galaga/asteroids/1/2022/06/03/19/04/3c2eef93a8488df7b6930d7269814312.json
galaga/asteroids/2/2022/05/18/18/47/c1eeccea771d779478d31cea730dc824.json
galaga/asteroids/default.json
galaga/asteroids/latest/latest.json
```

### Download Galaga JSON file to work on.

`% arcade galaga download -A toe_nail.arc -p galaga/asteroids/default.json`

```
Galaga galaga/asteroids/default.json downloaded to /Users/andy.dunlap/tmp/arcade/toe_nail.arc.json
{
    "user": "andy.dunlap",
    "createTime": "2022/05/02/07/32",
    "name": "toe_nail.arc",
    "version": 1,
    "components": {
        "asteroids-eks": {
            "location": "gsd/asteroids-eks/default.json",
            "overrides": {}
        }
    }
}
```
**Downloaded Galaga JSON files will have their name field set to the ARCADE name.**

`% cat ~/tmp/arcade/toe_nail.arc.json`

```
{
    "user": "andy.dunlap",
    "createTime": "2022/05/02/07/32",
    "name": "toe_nail.arc",
    "version": 1,
    "components": {
        "asteroids-eks": {
            "location": "gsd/asteroids-eks/default.json",
            "overrides": {}
        }
    }
}
```

### Add an override to an existing component.

`% arcade galaga add -A toe_nail.arc -p gsd/asteroids-eks/default.json -o services/nodegroup/service_options/asteroids/nodes=6`

```
{'components': {'asteroids-eks': {'location': 'gsd/asteroids-eks/default.json',
                                  'overrides': {'services/nodegroup/service_options/asteroids/nodes': 6}}},
 'createTime': '2022/07/01/17/13',
 'name': 'toe_nail.arc',
 'user': 'andy.dunlap',
 'version': 1}
 ```

### Get a list of GSDs to use for components in a Galaga JSON file.

`% arcade galaga find --gsd`

```
gsd/asteroids-eks/1/2022/04/26/14/58/d077bb17ef378a06491c7ab197b12757.json
gsd/asteroids-eks/2/2022/05/16/21/29/d077bb17ef378a06491c7ab197b12757.json
gsd/asteroids-eks/default.json
gsd/asteroids-eks/latest/latest.json
gsd/asteroids-msk/1/2022/05/04/19/00/a1b9fa5b30c12fd8aa2f2d4bd916d14b.json
gsd/asteroids-msk/default.json
gsd/asteroids-msk/latest/latest.json
gsd/log-relay/1/2022/06/15/17/30/f24d01c7e302edd2d59b4e5c4ef81b1c.json
gsd/log-relay/2/2022/05/25/22/36/f24d01c7e302edd2d59b4e5c4ef81b1c.json
gsd/log-relay/default.json
gsd/log-relay/latest/latest.json
```

### Add a component to a Galaga JSON file.

`% arcade galaga add -A toe_nail.arc -p gsd/log-relay/default.json`

```
{'components': {'asteroids-eks': {'location': 'gsd/asteroids-eks/default.json',
                                  'overrides': {'services/nodegroup/service_options/asteroids/nodes': 6}},
                'log-relay': {'location': 'gsd/log-relay/default.json',
                              'overrides': {}}},
 'createTime': '2022/07/05/16/07',
 'name': 'toe_nail.arc',
 'user': 'andy.dunlap',
 'version': 1}
Galaga toe_nail.arc is modified under /Users/andy.dunlap/tmp/arcade/toe_nail.arc.json
```

### Remove an override from a component within a Galaga JSON file.

`% arcade galaga remove -A toe_nail.arc -p gsd/asteroids-eks/default.json -o services/nodegroup/service_options/asteroids/nodes=6`

```
{'components': {'asteroids-eks': {'location': 'gsd/asteroids-eks/default.json',
                                  'overrides': {}},
                'log-relay': {'location': 'gsd/log-relay/default.json',
                              'overrides': {}}},
 'createTime': '2022/07/05/16/10',
 'name': 'toe_nail.arc',
 'user': 'andy.dunlap',
 'version': 1}
Galaga toe_nail.arc is modified under /Users/andy.dunlap/tmp/arcade/toe_nail.arc.json
```

### Remove a component and any overrides from within a Galaga JSON file.

`% arcade galaga remove -A toe_nail.arc -p gsd/asteroids-eks/default.json`

```
{'components': {'log-relay': {'location': 'gsd/log-relay/default.json',
                              'overrides': {}}},
 'createTime': '2022/07/05/16/11',
 'name': 'toe_nail.arc',
 'user': 'andy.dunlap',
 'version': 1}
Galaga toe_nail.arc is modified under /Users/andy.dunlap/tmp/arcade/toe_nail.arc.json
```

### Upload Galaga JSON

`% arcade galaga upload -f ~/tmp/arcade/toe_nail.arc.json -t default`

```
asd-7737cbfb8a57f71c43d41dfac2a2631e galaga/toe_nail.arc/2/2022/07/05/18/17/852308b2009aeca1d80c9423b2c9d9d8.json
asd-7737cbfb8a57f71c43d41dfac2a2631e galaga/toe_nail.arc/latest/latest.json
asd-7737cbfb8a57f71c43d41dfac2a2631e galaga/toe_nail.arc/default.json`
```
