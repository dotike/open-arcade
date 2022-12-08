# **GALAGA**

![image info](./marquee/galaga_marquee.jpg)

## GALAGA account initialization

Only needs to be done once per AWS account

### upload GSD schema

> `% arcade gsd init`

### upload GALAGA schema

> `% arcade gsd init -s misc/galaga/schema/galaga-schema.json`

### upload default GSDs

> `% arcade gsd upload -f libexec/galaga-modules/secretsmanager/secretsmanager.json -t default`

> `% arcade gsd upload -f libexec/galaga-modules/asteroids-eks/asteroids-eks.json -t default`

> `% arcade gsd upload -f libexec/galaga-modules/parameterstore/parameterstore.json -t default`

> `% arcade gsd upload -f libexec/galaga-modules/asteroids-msk/asteroids-msk.json -t default`

### upload default GALAGAs

> `% arcade galaga upload -f misc/galaga/galaga-examples/asteroids.json -t default`

> `% arcade galaga upload -f misc/galaga/galaga-examples/aoa.json -t default`

### Create eks_admin_role

> `% arcade galaga module asteroids-eks init`
