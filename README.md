# spmc-logger
This is a single writer multi reader logger. If message `x` is written to the logger, `x` isn't dropped from the logger till `y` number of readers have read it. 

# usage
```rust
Logger::new(NUM_OF_READERS, LOGGER_BUFFER_SIZE)
// Eg. This means this logger will hold a maximum of 100 messages and will drop a single message when 
// 3 readers have read it.
let l = Logger::new(3, 100)
// writing and reading
// Thread A
l.write("hello world")
// Thread B
// message can be an error if more readers outside the quorum is trying to read a message.
// it can be none if we've read all the messages in the buffer and some if there is a message to be read.
match l.read() {
    Ok(Some(message)) => println!(message),
    Ok(None) => _,
    Err(e) => _
}
```

# Example
The `it_works` test in `src/lib.rs` is a good example.



