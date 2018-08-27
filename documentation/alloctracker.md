# Alloctracer

	Used for memory leak detection by tracking memory allocation: [(addr, size, calls)]

## Files

> * [include/alloctracker.hh](include/alloctracker.hh) - class declaration
> * [core/alloctracker.cc](core/alloctracker.cc) - class implementation

## Detail

	class alloc_tracker

	Use linked list implemented by using array with index to record allocated nodes and free nods

```
	------------------------------------
	| addr | addr | addr | addr | addr |
	| size | size | size | size | size |
	| ...  | ...  | ...  | ...  | ...  |
	| next | next | next | next | next |
	------------------------------------
	   v      ^      ^v     ^v     ^v
	   |______|______||_____||_____||
	          |_____________________|
```

---

```
	void alloc_tracker::remember(void *addr, int size);
```
	
	Append an allocated node (addr, size, calls)
		calls - function stack: a.() -> b.() -> c.()

---

```
	void alloc_tracker::forget(void *addr)
```

	Find and free an allocated node