use chrono::Utc;
use std::{collections::HashMap, time::Instant};

use colored::Colorize;

pub struct Logger {
    timer_results: HashMap<String, u128>,
    current_timers: HashMap<String, Instant>,
    counters: HashMap<String, usize>,
}

fn get_time_prefix() -> String {
    format!(
        "{}{}{}",
        "[".cyan(),
        Utc::now().to_rfc3339().cyan(),
        "]".cyan()
    )
}

impl Logger {
    pub fn new() -> Self {
        Logger {
            timer_results: HashMap::new(),
            current_timers: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    pub fn warn(msg: &str) {
        println!(
            "{}{}{}",
            get_time_prefix(),
            " WARN: ".yellow(),
            msg.yellow()
        )
    }

    pub fn error(msg: &str) {
        println!("{}{}{}", get_time_prefix(), " ERR: ".red(), msg.red())
    }

    pub fn error_panic(msg: &str) -> ! {
        println!("{}{}{}", get_time_prefix(), " ERR PANIC: ".red(), msg.red());
        panic!()
    }

    pub fn info(msg: &str) {
        println!("{}{}{}", get_time_prefix(), " INFO: ".cyan(), msg.cyan())
    }

    pub fn success(msg: &str) {
        println!("{}{}{}", get_time_prefix(), " INFO: ".green(), msg.green())
    }

    pub fn start_timer(&mut self, key: &str) {
        self.current_timers
            .insert(key.to_string(), std::time::Instant::now());
    }

    pub fn incement_counter(&mut self, key: &str, amount: &usize) {
        let &value = self.counters.get(key).unwrap_or(&0);

        self.counters.insert(key.to_string(), value + amount);
    }

    pub fn stop_timer(&mut self, key: &str) {
        let Some(&timer) = self.current_timers.get(key) else {
            return;
        };

        self.current_timers.remove(key);

        let current_elapsed = *self.timer_results.get(key).unwrap_or(&0);

        self.timer_results.insert(
            key.to_string(),
            current_elapsed + timer.elapsed().as_millis(),
        );
    }

    pub fn consume(&mut self) {
        println!("{}", "Consumed Timers:".bold().blue());

        for (key, total_elapsed) in self.timer_results.drain() {
            println!(
                "{} {}ms {}",
                format!("- {:<20}", key).cyan(),
                total_elapsed.to_string().bold(),
                "(this run)".dimmed()
            );
        }
        println!("{}", "Consumed Counters:".bold().yellow());

        for (key, total) in self.counters.drain() {
            println!(
                "{} {} {}",
                format!("- {:<20}", key).yellow(),
                total.to_string().bold(),
                "(this run)".dimmed()
            );
        }
    }
}
