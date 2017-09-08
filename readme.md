# pyfstack
[![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)

python binding for f-stack

## install
 run `python setup.py install`

## documentation
pyfstack exports four modules: `fstack`, `socket`, `select`, `fcntl`.

### fstack
this module used to init f-stack and run loop function.
#### Fstack Objects
`fstack.Fstack(config_file, proc_type, proc_id)`

Constructor of `fstack.Fstack` class, the arguments are same as `ff_init`
+ `run(fn, *args, **kwargs)`: run the loop callback, `args` and `kwargs` is the arguments of `fn`

you can use the following code to init f-stack and run the loop callback

    ffobj = fstack.Fstack(conf, proc_type, proc_id)
    ffobj.run(loop_cb, arg1, ...)

### socket
similar to the builtin `socket` module

### select
similar to the builtin `select` module

### fcntl
similar to the builtin `fcntl` module
