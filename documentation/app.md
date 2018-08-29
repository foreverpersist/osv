# App

	Represents an executing program

## Files

> * [include/osv/app.hh](include/osv/app.hh) - class declaration
> * [include/osv/app.cc](include/osv/app.cc) - class implementation

## Detail

### app_registry

	class app_registry

	Manage an application list

---

```
	void app_registry::join()
```

	Wait until all applications ternimate

---

```
	bool app_registry::remove(application* app)
```

	Remove an application

---

```
	void app_registry::push(shared_app_t app)
```

	Add an application

### app_runtime

	class app_runtime

	Just a wrapper of class application
	Parent and children have the same app_runtime

### application

	class application

	Represents an executing program which may include some children

---

	public

---

```
	static shared_app_t application::get_current()
```

	Get parent (or itself)

---

```
	static shared_app_t application::run(const std::string& command,
                      const std::vector<std::string>& args,
                      bool new_program,
                      const std::unordered_map<std::string, std::string> *env,
                      const std::string& main_function_name,
                      std::function<void()> post_main)
```

	Create a child, start it, then push it to app registry

---

```
	static int application::join_all()
```

	Wait until all application in registry terminate

---

```
	int application::join()
```

	Wait until application terminates

---

```
	static shared_app_t application::run_and_join(const std::string& command,
                      const std::vector<std::string>& args,
                      bool new_program,
                      const std::unordered_map<std::string, std::string> *env,
                      waiter* setup_waiter,
                      const std::string& main_function_name,
                      std::function<void()> post_main)
```

	Create a child, run it in current thread

---

```
	static void application::on_termination_request(std::function<void()> callback)
```

	Add callback, or execute it if app is doing callback

---

```
	void application::request_termination()
```

	Execute callbacks in parent, or start a new thread for callbacks in children

---

```
	static bool application::unsafe_stop_and_abandon_other_threads()
```

	Unsafely stop all other threads whose runtime is the same

---

```
	int application::get_return_code()
```

	Get `_return_code`

---

```
	std::string application::get_command()
```

	Get `_command`

---

```
	pid_t application::get_main_thread_id()
```

	Get tid of `_thread`

---

```
	elf::program *application::program()
```

	Get `_program`

---

	private

---

```
	void application::new_program()
```

	Create a new ELF `program`?

---

```
	void application::clone_osv_environ()
```

	Use `putenv` in `libenviron.so` to set environments

	[FIXME: memory leak]

---

```
	void application::set_environ(const std::string &key, const std::string &value,
                              bool new_program)
```

	Use `setenv` in `libenviron.so` to set new environments

	[FIXME: memory leak]

---

```
	void application::merge_in_environ(bool new_program,
        const std::unordered_map<std::string, std::string> *env)
```

	Just invoke `set_environ`

---

```
	void application::start()
```

	Create a new thread to run `main`

---

```
	void application::start_and_join(waiter* setup_waiter)
```

	Run `main` in current thread

---

```
	void application::main()
```

	Initialize application ELF, run `run_main` -> `_post_main` or `_entry_point`

---

```
	void application::prepare_argv(elf::program *program)
```

	Allocate memory for argv and env, load library vdso if avaiable

---

```
	void application::run_main()
```

	Run `_main`
	
---

	external

---

```
	void with_all_app_threads(std::function<void(sched::thread &)> f, sched::thread& th1)

	Execute f on all threads which belong to same app as t1 does.
```

---

```
	extern "C" void __libc_start_main(int (*main)(int, char**), int, char**,
    void(*)(), void(*)(), void(*)(), void*)
```

	Get app of current thread, run `main` of app