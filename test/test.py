#!/usr/bin/env python3
"""
Test script with simple functions to trace with our eBPF program.
"""
import time

def hello_world(name="World"):
    """A simple function that prints a greeting."""
    print(f"Hello, {name}!")
    return f"Hello, {name}!"

def calculate_sum(a, b, c=0):
    """Calculate the sum of two or three numbers."""
    result = a + b + c
    print(f"Sum of {a}, {b}, and {c} is {result}")
    return result

def fibonacci(n):
    """Calculate the nth Fibonacci number."""
    if n <= 0:
        return 0
    elif n == 1:
        return 1
    else:
        return fibonacci(n-1) + fibonacci(n-2)

if __name__ == "__main__":
    print("Starting test script...")
    
    # Call our functions multiple times
    for i in range(3):
        hello_world(f"User {i}")
        time.sleep(0.5)
        
    for i in range(2):
        calculate_sum(i, i+1, i+2)
        time.sleep(0.5)
    
    print("Calculating Fibonacci numbers...")
    for i in range(5):
        result = fibonacci(i)
        print(f"Fibonacci({i}) = {result}")
        time.sleep(0.5)
    
    print("Test script completed!")