# Walkthrough: Creating an Attacker in Incalmo

This guide explains how to create a minimal, working attacker for the Incalmo framework.

---

## 1. Create Your Hello World Strategy File

1. Navigate to `incalmo/core/strategies/`.
2. Create a new file, e.g., `hello_world_strategy.py`.

---

## 3. Implement the Attack Strategy

Use the template found in incalmo/core/strategies/testers/hello_world_strategy.py to create a new attack strategy.
---

## 4. Register the Strategy

To use your new strategy, you must register it in the configuration. This is done in the config file `config/config.json`. 

There are two kinds of strategies, found in `config/attacker_config.py`, the LLMStrategyConfig (to be used for strategies that are driven by LLMs) and StateMachineConfig (to be used for any non-LLM driven strategy). Format the config file's `strategy` field to adhere to whichever type of strategy you choose. 

`config/config.json` for the hello world template strategy (follows StateMachineConfig strategy config):

```json
{
  "name": "test",
  "strategy": {
    "name": "hello_world_strategy" 
  },
  "environment": "EquifaxLarge", // environment to test on, determines how much initial information the attacker has. For more detail, see incalmo/core/services/environment_initializer.py
  "c2c_server": "http://192.168.199.10:8888" // ip address of attacker docker container 
}
```

---

## 5A. Deploy Strategy on Docker Environment

1. `cd docker`
2. `docker-compose up`
3. Open new terminal
4. `python3 main.py`
5. Output log folder will appear in the output directory

## 5B. Deploy Strategy on Network (MHBench)

1. 

---
