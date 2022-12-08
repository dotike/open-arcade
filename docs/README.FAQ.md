# Frequently Asked Questions (FAQ)

---

## What is an arcade
  - An arcade is a collection of resources, software, and services. The arcade is comprised of three layers, they are top to bottom

    1. Asteroid
    2. Galaga
    3. Gravitar

---

## Where is ARCADE documentation?
  - The ARCADE tool set is documented for use in the tool itself:
    - All commands support '-h' help options which describe their use.
    - The tool contains how-to and quickstart information in README files,
      - README.md in the root of the repository
      - /docs/ in the root of this repository has topical documentation (including this FAQ!)
  - wiki information about ARCADE is limited to design and business documents

---

## What is a GRV.
  - A GRV is an AWS VPC with a specific set of AWS resources and configurations. The GRV represents the Gravatar layer.

---

### How do I create a GRV.
  - The top level README.md (arcade/README.md) has detailed instructions of how to create a GRV. The first step is to setup the arcade environment.

```
% cd $HOME/Git/arcade
% source arcade-set -n
```
  Then follow the steps in the section labeled **Gravatar**

---
### I just hit AWS VPC quotas in my account.  How many VPC's do I need?

ARCADE tools are intended to support 'N instances' of infrastructure and applications running simultaneously.
Operators of ARCADEs are the only people who know how many "N" should be.

Here's some sizing guidance:
For VPC's, AWS defaults to 5 VPC's per each Region available to your account.  This is adjustable, and based on our experiences, AWS can be asked to increase this to 100's of VPCs per Region.  Given that the ARCADE default configuration for IPv4 supernet slicing for ~250 ARCADES in a single AWS account, you *may* ask AWS to increase this quota to several hundred VPC's per region.

For More information, see Amazon documentation for VPC quotas: https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html

---

### What is the purpose of buildreport.txt output during GRV creation?  Is it a log?
  - The 'buildreport.txt' which is generated during gravitar builds is useful for debugging, as it captures *all* output from that GRAVITAR layer build.  Although there are many wallclock date-stamps, there is no effort to normalize the output- a mix of json responses, newlines, and date-stamped lines are all dumped as soon as they are generated in the GRV layer program.
  - This 'buildreport.txt' is useful for debugging and development, and not much more.

---

### How can I change AWS VPC Subnet ACL's in an ARCADE?
  - Each ARCADE contains three Subnet ACL's, one for each of the logical network layers configureable in `etc/grv_netbase.conf`.
  - Each of these ACL's are available for ARCADE operators/users to configure and operate, and they will be named/tagged to match the ARCADE they belong to.
  - Most packet filtering is specifically handled via Security Groups, not these ACL's.
  - ACL use is described here: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html

---

### How can I find out which AWS account I am configured to use?
  - `$ arcade test aws -v`
  - The "verbose" flag for `test aws` prints the AWS account ID, as a part of printing a handy URL to log into the console.

```
$ arcade test aws -v
my.username
console: https://012345678901.signin.aws.amazon.com/console
$
```

---

### Can I use Python Virtual Enviornment with ARCADE tools?
  - Yes, we welcome this practice, but it's not supported behavior.
  - If you want to use Python virtual enviornments to segregate ARCADE python from your system, you may do it, but based on the many ways this can be used, Python virtualenv use is not supported by the IP Tools team.  Regardless, here are the basic steps:
    * Setup your enviornment like we did above:
      * `source arcade-set -n`
    * Create Virtual Environment:
      * `python3 -m venv venv`
    * Activate the Environment:
      * `source venv/bin/activate`
    * Finally install required python packages:
      * `pip install -r requirements.txt`

---
### Can I change the tmp directory which ARCADE uses?
  - Yes, you can choose a temp directory to live wherer you wish
  - ARCADE build, scratch, and temporary files are written to a tmp/ directory, the default location is ${HOME}/tmp/arcade.

> If you prefer to change this location, you may set an ENV var in your profile,
>
> ```bash
> # for ~/.bashrc ~/.zshrc or ~/.profile
> export ATMP=$HOME/any/path/your_user_can_write_to
> ```

---
### If you want detailed verbose output with `-v` on `arcade galaga run` then set the following environment variable.

```shell
export GALAGA_VERBOSE=True
```
