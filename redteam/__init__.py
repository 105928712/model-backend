import importlib
import pkgutil

from urllib.error import URLError # special case meaning server is probably not running, worth handling seperately

def run():
    print("Running redteam scripts")

    # discover + keep only modules with a callable run()
    scripts = []
    for mod_info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if mod_info.name.startswith("_"):
            continue  # not __init__ or __main__ lol

        module = importlib.import_module(f"{__name__}.{mod_info.name}")  # i.e. redteam.sql_injection
        script_run = getattr(module, "run", None)                        # i.e. redteam.sql_injection.run
        if callable(script_run):
            scripts.append((mod_info.name, script_run))

    for index, (name, script_run) in enumerate(scripts):
        print(f"[{index + 1}/{len(scripts)}] Running {name}")
        try:
            script_run()
        except Exception as e:
            if isinstance(e, URLError): raise RuntimeError("Is the server running?"); exit(1)
            print(f"[!] {name} failed:", e.__class__.__name__, e)