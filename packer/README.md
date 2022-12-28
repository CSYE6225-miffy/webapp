to enter the directory
```
pwd ./webapp
``` 

to validate packer syntax
```
packer validate ./packer/ami.pkr.hcl
```

to build AMI
```
AWS_PROFILE=dev packer build ami.pkr.hcl   
```
