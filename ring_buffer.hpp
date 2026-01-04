#pragma once
#include <vector>
#include <mutex>
#include <condition_variable>
#include <cstdint>

class RingBuffer {
public:
  explicit RingBuffer(size_t cap) : buf(cap), cap(cap) {}

  void push_bytes(const uint8_t* data, size_t n){
    size_t i = 0;
    while (i < n){
      std::unique_lock<std::mutex> lk(m);
      cv_not_full.wait(lk, [&]{ return size < cap; });

      buf[write_idx] = data[i++];
      write_idx = (write_idx + 1) % cap;
      size++;

      lk.unlock();
      cv_not_empty.notify_one();
    }
  }

  void pop_bytes(uint8_t* out, size_t n){
    size_t i = 0;
    while (i < n){
      std::unique_lock<std::mutex> lk(m);
      cv_not_empty.wait(lk, [&]{ return size > 0; });

      out[i++] = buf[read_idx];
      read_idx = (read_idx + 1) % cap;
      size--;

      lk.unlock();
      cv_not_full.notify_one();
    }
  }

private:
  std::vector<uint8_t> buf;
  size_t cap;

  size_t read_idx = 0, write_idx = 0, size = 0;
  std::mutex m;
  std::condition_variable cv_not_full, cv_not_empty;
};
