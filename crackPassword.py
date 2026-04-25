import time


all_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

def crackPassword(target_password, password_length):
    indices = [0] * password_length

    while True:
        guess = "".join(all_chars[i] for i in indices)
        print(guess)

        if guess == target_password:
            print(f"Password Found: {guess}")
            return

        pos = password_length - 1
        while pos >= 0:
            indices[pos] += 1
            if indices[pos] < len(all_chars):
                break
            indices[pos] = 0
            pos -= 1
        else:
            print("Password not found.")
            return
        
def timeEstimation(password_length):
    numChars = len(all_chars)
    count = 0
    indices = [0, 0, 0 ,0]
    start = time.perf_counter()

    pos = 3
    while pos >= 0:
        indices[pos] += 1
        if indices[pos] < numChars:
            break
        indices[pos] = 0
        pos -= 1
    count += 1
    indices[pos] = 0

    stop = time.perf_counter()

    elapsed = stop - start

    print("Elapsed: ", elapsed)

    per_second = count / elapsed

    print("Per Second: ", per_second)

    total_combinations = numChars ** password_length

    total_seconds = total_combinations / per_second

    formatTime(total_seconds)


def formatTime(total_seconds):
    total_seconds = int(total_seconds)
    
    days    = total_seconds // 86400
    remaining = total_seconds % 86400
    
    hours   = remaining // 3600
    remaining = remaining % 3600
    
    minutes = remaining // 60
    seconds = remaining % 60
    
    print(f"{days}d {hours}h {minutes}m {seconds}s")



if __name__ == "__main__":
    user_input = input("Enter a password: ")
    
    if len(user_input) > 8:
        timeEstimation(len(user_input))
    else:
        crackPassword(user_input, len(user_input))