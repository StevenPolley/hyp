# hyp | Hide Your Ports

hyp is a [port knocking](https://www.youtube.com/watch?v=a7VJZEJVhD0) implementation written in Go, using spread-spectrum UDP as an authentication mechanism.  It enables trusted devices to access services over the internet, wherever they are, and without the service being publicly accessible.  The benefit is that the ports are not open publicly on the internet, they won't show in a port scan and are therefore less likely to be attacked by a threat actor. 

hyp provides security through obscurity.  Security through obscurity tends to have a negative connotation, at least in the IT world.  I don't agree with this, but it's prescribed as being bad.  My belief is security through obscurity is a "further step" one can take to eliminate a certain class of threats.  It by no means should be the only mechanism of protection, but instead should be incorporated only as part of a layered defense.  

### Physical World Analogy

*Scenario:* You drive to the grocery store and you happen to have your laptop computer with you in the car.  You're worried someone may break into your car and steal your laptop, but luckily you have some options to consider before you leave the car to go into the store:

1. You could leave your laptop sitting where it is, on the passenger seat
2. You could conceal the laptop from outside view

Option 1 is the default option and is analogous to having your services internet-accessible.  Option 2 is similar to what port knocking is trying to achieve.  In either case, there still exists some risk that your laptop will be stolen in a random bip, which is why port knocking should not be your sole focus when it comes to your security strategy and should instead be something you can use to reduce the risk of drive-by attacks.

### Brute Force Simple Overview

To put it in simple terms, hyp requires an adversary to guess a number between 1 and 18,446,744,073,709,551,615 within 90 seconds.  Each guess attempt requires four ordered UDP datagrams to be sent.  The requirement for correct order on arrival, multiple network paths, and network latency means the datagrams have to be spaced out and transmitted one at a time with time spent waiting before the next datagram is sent.  An odd but perhaps useful implication of this is that the further away you are (higher latency), the less reliable guess attempts you can make before the number changes.  With 20ms of latency, you can perform a maximum of 4,500 reliable guesses.  With 100ms of latency, you can only perform a maximum of 900 reliable guesses.

### Protection Against Replay Attacks

Most port-knocking implementations are susceptible to replay attacks, a network operator could intercept your authentic knock sequence and then replay the sequence.  hyp works around this by using 64-bit time-based one-time tokens.  The 64 bits of the token are then divided into 4x16-bit unsigned integers representing a port number.  

hyp supports a clock skew of up to 30 seconds between client and server.  

### TBD: Protection Against Sweeping Attacks

~~hyp protects against sweeping attacks where an adversary modulates over the entire port range multiple times by ensuring the authentic knock sequence is strict and ordered correctly.  If the first port is guessed, but the next pack arrives and is the incorrect second port in the sequence, the progress gets reset.~~

### Known Weaknesses

* Lossy networks can result in the knock sequence failing
* Networks with latency > 500ms can result in the knock sequence failing if packets arrive out of order

### References

* RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm
* RFC 6238 - TOTP: Time-Based One-Time Password Algorithm
* Techniques for Lightweight Concealment and Authentication in IP Networks