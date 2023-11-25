use ring::rand::SecureRandom;
use ring::{hmac, rand};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering::{AcqRel, SeqCst}};
use std::sync::RwLock;
use std::thread::{self, ThreadId};

#[derive(Debug)]
pub struct Message {
    bytes: Vec<u8>,
    hash: hmac::Tag,
    readers: AtomicUsize,
}

impl Clone for Message {
    fn clone(&self) -> Self {
        Message { 
            bytes: self.bytes.clone(), 
            hash: self.hash, 
            readers: AtomicUsize::new(self.readers.load(SeqCst)) }
    }
}

pub struct Logger {
    num_readers: usize,
    readers: RwLock<HashMap<ThreadId, usize>>,
    messages: Vec<Message>,
    size: usize,
    key: hmac::Key,
}

impl Logger {
    pub fn new(num_readers: usize, size: usize) -> Self {
        // Create key for signing SHA256 hashes
        let mut buf = [0u8; 48];
        let rng = rand::SystemRandom::new();
        let _ = rng.fill(&mut buf);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &buf);

        Self {
            num_readers,
            readers: RwLock::new(HashMap::with_capacity(num_readers)),
            messages: Vec::with_capacity(size),
            size,
            key,
        }
    }
}

pub struct Response {
    pub message: Vec<u8>,
    pub hash: hmac::Tag,
    pub is_valid: bool,
}

pub trait Log {
    fn write(&mut self, data: &[u8]) -> Result<(), usize>;
    fn read(&mut self) -> Result<Option<Response>, usize>;
}

impl Log for Logger {
    /// Error Code 1 means the buffer is full
    fn write(&mut self, data: &[u8]) -> Result<(), usize> {
        let thread_id = thread::current().id();
        eprintln!("writer: thread {:?} is writing...", thread_id);
        if self.messages.len() >= self.size {
            eprintln!("writer: buffer is full!");
            return Err(1);
        }
        let hash = hmac::sign(&self.key, data);
        let message = Message {
            readers: AtomicUsize::new(0),
            bytes: data.to_vec(),
            hash,
        };

        self.messages.push(message);
        Ok(())
    }

    /// Error Code 2 means there are too many readers (ie. greater than the quorum)
    fn read(&mut self) -> Result<Option<Response>, usize> {
        let thread_id = thread::current().id();
        // eprintln!("thread {:?} is reading...", thread_id);
        // use a read lock here to allow other threads check this condition
        let readers = self.readers.read().unwrap();
        // if there are more readers than necessary, then return early as only 3 readers are needed for our quorum.
        if readers.len() > self.num_readers {
            eprintln!("reader: too many readers. dropping thread {:?}", thread_id);
            return Err(2);
        }

        let thread_count = match readers.get(&thread_id) {
            Some(&i) => i,
            None => 0,
        };

        drop(readers);

        // return none if we're at the end of the buffer
        if self.messages.is_empty() || thread_count > 0 && thread_count > self.messages.len() - 1 {
            eprintln!("reader: at the end of the buffer {} {}", self.messages.len(), thread_count);
            return Ok(None);
        }

        // get message before removing it
        let m = self.messages[thread_count].clone();

        let is_valid = hmac::verify(
            &self.key,
            m.bytes.as_slice(),
            m.hash.as_ref(),
        )
        .is_ok();

        let _ = self.messages[thread_count].readers.fetch_add(1, AcqRel);
        let current_readers = self.messages[thread_count].readers.get_mut();

        let mut new_thread_count = thread_count;
        
        if current_readers >= &mut self.num_readers {
            eprintln!("reader: removing message {} as all readers have read it", thread_count);
            self.messages.remove(thread_count);
        }else {
            new_thread_count+=1;
        }

        let mut readers = self.readers.write().unwrap();
        readers.insert(thread_id, new_thread_count);

        Ok(Some(Response {
            message: m.bytes.to_vec(),
            hash: m.hash,
            is_valid,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::{Arc, Mutex}};
    #[test]
    fn it_works() {
        let logger = Arc::new(Mutex::new(Logger::new(3, 100)));
        {
            let l = logger.clone();
            let original_thread = thread::spawn(move || {
                for x in 0..10 {
                    let message = format!("Hello my name is {}", x);
                    let mut l = l.lock().unwrap();
                    let _ = l.write(message.as_bytes());
                }
            });

            original_thread.join().unwrap();
        }

        let threads = (0..3).map(|_| {
            let l = logger.clone();
            thread::spawn(move || {
                let mut l = l.lock().unwrap();
                for _ in 0..10 {
                     match  l.read() {
                        Ok(Some(res)) => {
                            let message: String = String::from_utf8(res.message).unwrap();
                            assert!(res.is_valid);
                            eprintln!("Receiver: {:?}", message)
                        },
                        Err(_e) => /* eprintln!("ERROR {:?}", e) */ (),
                        Ok(None) => /* eprintln!("nothing is happening") */ ()
                    }
                }
            })
        });

        for handle in threads {
            handle.join().unwrap();
        }

        let l = logger.lock().unwrap();

        assert_eq!(l.messages.len(), 0);
    }
}
