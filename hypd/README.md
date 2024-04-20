# hypd | Hide Your Ports Daemon

hypd is the pork knocking daemon which listens for incoming authentic knock sequences.  

### Usage

Running hypd requires generating secrets which are then shared with hyp clients.  hypd is used to generate these secrets, and it's recommended you create a directory just for hyp secrets.

```bash
# Example: create a directory named secrets
mkdir -p secrets

# Then generate a secret file in this directory
./hypd generate secret > secrets/my-first-secret
```

It's recommended you generate a secret for each trusted agent so you can granularly control revocation just by removing a secret file from the secrets directory.

Running hypd requires specifying a configuration file.  It's recommended you generate the default configuration file and then edit it afterwards.

```bash
# Create a default configuration file
./hypd generate defaultconfig > hypd.conf
```

Make sure you take the time to review the hypd.conf file and edit it to your liking, this is the most important step.  

Once you have set your config file, you can finally run hypd.

```bash
# As root or sudo, specify the configuration file
sudo ./hypd server hypd.conf
```