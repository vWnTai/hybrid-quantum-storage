import sys
from gui import PQCApp

def main():
    try:
        app = PQCApp()
        app.mainloop()
    except Exception as e:
        print(f"Fatal Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
