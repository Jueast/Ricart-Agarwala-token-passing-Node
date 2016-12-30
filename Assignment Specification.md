## MIE-DSV Semestral Work Specification
*Zhengdong Wang*
*11.2016*

### Function
In this semestral work, I will build a variable sharing system among 5-10 nodes. The access mechanism will be realized via mutual exclusion. The variable will be stored in a specific server(**I hope it will not violent any requirements**, or maybe I will make use of some leader election techenique to choose server in nodes). It will have at least these functions: read/write variable/memory, login, logout, crash.
### Problem Class
Obviously **mutual exclusion**. **leader election** is optional

### Algorithm
For mutual exclusion, I will use **Ricart-Agrawala Algorithm**.

### Framework
I will use **python socket** to communicate among nodes.
