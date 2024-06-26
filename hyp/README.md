# hyp | Hide Your Ports Client

The hyp client is used on machines to perform an authentic knock sequence.  

### Usage

You can use -h to get help for hyp and all its commands.  When figuring out how to do something, -h is your friend.

```bash
# Get general hyp help
./hyp -h

# Get help specific to the hyp knock command
./hyp knock -h
```

In order to use the hyp client, it must have the secret.  Secrets are generated by hypd, the knock daemon.  See the hypd README.md file for more information about generating secrets.

Once you have the secret, you can then perform an authentic knock sequence to a server.

```bash
# Assumes secret is in file named my-first-secret in same directory
./hyp knock 8.69.4.20 --secret my-first-secret

# If you omit --secret, hyp will look for a file named hyp.secret
./hyp knock 8.69.4.20
```

This will perform a single one-shot knock sequence and then hyp will exit.  You can also run hyp in a persistent mode where it will perform an authentic knock sequence at a specified interval.

```bash
# Performs an authentic knock sequence every 45 minutes
./hyp knock 8.69.4.20 --refreshtime=45
```
