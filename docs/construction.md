# Lattice core

This code follows the algebra in Section 7.1 of
[Non-interactive Blind Signatures: Post-quantum and Stronger Security](https://eprint.iacr.org/2024/614.pdf),
ePrint pages 44–45. The Bonsai sampling step is described on page 18.

The public matrices are $A,B,C\in\mathbb Z_q^{n\times 2m}$, with
$A=[A_L\mid A_R]$ and $C=[C_L\mid C_R]$. Vectors keep their signed integer
coordinates for norm checks; matrix equations are evaluated modulo $q$.
Write $s$ for the paper's Gaussian parameter $\varsigma$, and set
$\beta=s\sqrt m$.

## Receiver and issuance

The receiver holds $x\in\mathbb Z^{2m}$ and a random string $\delta$. Its
public key is

$$
t=Ax+H(\delta)\pmod q.
$$

The paper samples $x$ with Gaussian parameter $s/m$. The issuer samples
$y\in\{-1,1\}^{2m}$ and a short preimage $z$ such that

$$
Cz+By=t\pmod q.
$$

The implementation checks this equation and the squared bounds

$$
\|x\|_2^2\le\frac{2s^2}{m},\qquad
\|z\|_2^2\le2ms^2.
$$

These are the paper's $\sqrt2\beta/m$ and $\sqrt2\beta$ bounds, squared.
The nonce entries must be the integers $-1$ or $1$.

Split $x=(x_{\rm top},x_{\rm bottom})$ and likewise $z$, each half having
length $m$. The receiver derives

$$
w=A_Lx_{\rm bottom}+A_Rz_{\rm bottom}\pmod q,
\qquad \mu=(w,\delta).
$$

Both inputs here are bottom halves. In the paper, the symbol $\perp$ in
this expression denotes a vector half, rather than an orthogonal projection.

## Sampling in this version

The sampler uses a finite table with weights proportional to
$\exp(-\pi k^2/s^2)$. Its finite cutoff and floating-point arithmetic make
it an approximation to the unbounded discrete Gaussian. The receiver uses
the same method with parameter $s/m$.

For a target $u=t-By$, issuance first samples $z_{\rm bottom}$. Keeping
that half fixed, it repeatedly samples $z_{\rm top}$ until

$$
C_Lz_{\rm top}=u-C_Rz_{\rm bottom}\pmod q.
$$

Accepted top halves have the finite sampler's distribution conditioned on
this equation. This preserves the independently sampled bottom half before
the full-vector norm check. Rejection sampling costs about $q^n$ trials
when the sampled syndromes are close to uniform; it becomes impractical as
the parameters grow. There is no trapdoor or secret signing key here, so
anyone can run this issuance procedure.

The signer matrix is sampled uniformly conditioned on $C_L$ having full row
rank. This is a test setup, rather than the paper's `TrapGen` algorithm.

`H` expands a domain-separated input with SHAKE256 and rejects candidates
outside a multiple of $q$ before reducing them. This avoids simple modulo
bias in the hash-to-vector step. It instantiates the paper's modeled random
oracle; it does not prove that model's security claims.

The default $n=2$, $m=8$, $q=17$, $s=8$ keeps the example small. These are
toy parameters and do not meet the paper's security requirements.

## Remaining signature layer

The full construction encrypts the witness $(x,y,z)$ and proves membership
in language $L_2$. Its signature is $\sigma=(\pi,ct)$, and public
verification checks that proof. Encryption and the NIZK are still to be
implemented. A successful relation check in this repository establishes
the displayed equations only; it is not final signature verification or
a demonstration of blindness or one-more unforgeability.
