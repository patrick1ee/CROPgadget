import sys
import subprocess

def run_program(program, argument):
    loop = True
    buflen = 0
    binary = False
    seg = True
    previous = 0
    min, max, mid = 0, 0, 0

    while loop:
        f = open('input', "w")
        string = "A" * int(buflen)
        f.write(string)

        try:
            process = subprocess.Popen([program, argument], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            exit_code = process.wait()
            
            output, error = process.communicate()
            
            print("Output:\n", output.decode())
            print("Error:\n", error.decode())
            
            print("Exit Code:", exit_code)

        except Exception as e:
            print("An error occurred:", str(e))

        if binary:
            if (exit_code == -11):
                if (max == mid or min ==mid):
                    loop = False
                max = mid
            else:
                min = mid

            mid = int(((max - min)/2) + min)
            buflen = mid

        if seg:
            if (exit_code == -11):
                binary = True
                seg = False
                min, max = previous, buflen
                mid = int(((max - min)/2) + min)
                buflen = mid

            else:
                previous = buflen
                difference = 1
                buflen += difference
            
    f.close()
    print("\nfinal buffer length:", buflen + 1)



run_program(sys.argv[1], sys.argv[2])