# GALAGA modules

## Description

 * GALAGA modules create infrastructure for a specific use case.
 * Each GALAGA module is a standalone set of scripts that work with all pieces necessary for the infrastructure.

## Development rules

 * Each GALAGA module is standalone.
 * Functions that create/destroy infrastructure are part of the modules library.
 * Functions that read or query infrastructure are part of the arclib.
 * No dependencies upon other GALAGA modules.
 * GALAGA modules are idempotent

For **arcade galaga create** and **arcade galaga module** to work, the scripts need to be named appropriately.
```
<MODULE_NAME>/<MODULE_NAME>-[create|read|update|destroy]

asteroids-eks/asteroids-eks-create
asteroids-eks/asteroids-eks-read
asteroids-eks/asteroids-eks-update
asteroids-eks/asteroids-eks-destroy
```
All 4 scripts must exist.
