import subprocess
import ctypes

def start_c_process():
    # Run the compiled C program
    subprocess.run("./vuln3-32", shell=True)

def find_allocated_memory_address():
    # Replace this with the size you allocated in your C program
    array_size = 10

    # Load the shared library (.so) file corresponding to the compiled C program
    lib = ctypes.CDLL("./vuln3-32.so")

    # Assuming that the C program stored the memory address in a variable named 'dynamicArray'
    memory_address = lib.dynamicArray

    # Print the allocated memory address
    print(f"Allocated memory address in Python: {hex(memory_address)}")

if __name__ == "__main__":
    start_c_process()
    find_allocated_memory_address()