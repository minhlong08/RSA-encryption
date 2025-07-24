"""
Benchmark file testing how many divisions per second can your machine do
"""
import time

N = 10_000_000
start = time.time()
for i in range(1, N):
    _ = 12345678901234567890 // i
end = time.time()

print(f"{N:,} divisions in {end - start:.2f} seconds")
print(f"{N / (end - start):,.0f} divisions per second")
