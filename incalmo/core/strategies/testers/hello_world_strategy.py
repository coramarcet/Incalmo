# Import necessary modules for creating an attacker strategy
from abc import ABC  # Abstract Base Class for inheritance
from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy  # Base class for all strategies

from config.attacker_config import AttackerConfig  # Configuration settings for the attacker, specified in config/config.json
from incalmo.core.actions.HighLevel import Scan  # High-level scan action

#! Control systems: Sense model react
#! OODA loop (Observe, Orient, Decide, Act)

#! Add this abstraction for S(p, w, t, a)
  #! Environment service is the world model
  #! Action: Scan, Lateral Move
  #! Telemetry
  #! Planning: BFS

#! Prototyping ideas from the literature for attack and defense
  #! Attack graph based defense
  #! AI planning for automated attack strategies
  #! RL, GEPA (p)

#! Action/Envrionment
  #! MOSIP
  
#! Personalized firewall defender 
  #! Easier way to create custom firewalls (send more than 5 connections)
  #! World model is based on the history of network + out of band information about the network + 
  #! + out of band information about the world
  
#! How do I test if the attacker is working correctly?
#! Scenario driven testing for the attacker and defender

#! Mental model of new attacker and new defense
#! How would prompt 

#! Having some visual way to show what an attacker and defender is doing
  #! Write down these different project ideas
  
#! abstraction for S(p, w, t, a)
#! Testing system for whether attacker and defender are working correctly
#! Creating strategies from techniques found in the literature
#! Visual debugger


# Define your custom strategy class
# This class inherits from IncalmoStrategy (provides base functionality) and ABC (abstract base class)
# The 'name' parameter registers this strategy so it can be selected in configuration files
class HelloWorldStrategy(IncalmoStrategy, ABC, name = "hello_world_strategy"):
    """
    A simple example strategy demonstrating basic attacker behavior patterns.
    
    This strategy serves as a template for students to understand how to create their own
    attack strategies in the Incalmo framework. 
    
    To Create Your Own Strategy:
    1. Copy this file and rename the class
    2. Update the 'name' parameter to be unique
    3. Modify __init__() to set up your specific requirements
    4. Implement your attack logic in step()
    5. Add your strategy file to the appropriate directory - incalmo/core/strategies/
    6. Add your strategy to the __init__.py file in the strategies directory
    """
    def __init__(self, config: AttackerConfig, **kwargs): 
        """
        Constructor for your custom strategy.
        
        Args:
            config: AttackerConfig object containing configuration settings
            **kwargs: Additional keyword arguments that can be passed to your strategy
        
        This method is called once when your strategy is instantiated.
        Use this to set up any initial state, variables, or configuration your strategy needs.
        """
        # Always call the parent constructor first to initialize base functionality
        super().__init__(config, **kwargs)

        # Set up logging - this creates a logger specifically for your strategy
        # Use this logger instead of print() statements for better output management
        self.logger = self.logging_service.setup_logger(logger_name="attacker")
        
        # Initialize any custom variables your strategy needs
        # Example: Track the current step in a multi-step attack
        self.cur_step = 0
        self.total_steps = 1  # Set how many steps your attack should take
        
    #! STEP 1: Gather information about the current environment
    def collect_telemetry(self) -> None:
        """
        Observe the current telemetry inputs.
        This method can be used to gather information about the environment before deciding on actions.
        
        In this example, I use existing services from Incalmo that gather telemetry and parse it into the world model,
        for the LLM to access, so this is a no-op. (See update_world_model() for how to access these services)
        """
        pass
    
    #! STEP 2: Update world model based on collected telemetry
    def update_world_model(self) -> dict:
        """
        Update internal world model 
        Look at c2_client functions(incalmo/api/server_api.py) and environment_state_service.network functions (incalmo/core/models/network/network.py)
        """
      
        agents = self.c2_client.get_agents()
        hosts = self.environment_state_service.network.get_all_hosts()
        subnets = self.environment_state_service.network.get_all_subnets()
        host = hosts[0]
        
        return {
            "agents": agents,
            "hosts": hosts,  
            "subnets": subnets,
            "host": host, 
        }
    
    #! STEP 3: Plan your next action based on the updated world model
    def planner(self, world_model: dict) -> None:
        """
        Update stateful processing based on updated world model / feed updated world model into planner.
        In this example I have no stateful processing or planning, so this is a no-op.
        
        """
        pass
    
    #! STEP 4: Execute your chosen action
    async def act(self, world_model: dict) -> None:
      """
      Execute actions based on the current plan.
      # You can find available actions in incalmo/core/actions/HighLevel/ or incalmo/core/actions/LowLevel/
      # High level actions call low level actions internally to perform complex tasks
      """
      events = await self.high_level_action_orchestrator.run_action(
        Scan(
          world_model["host"],
          world_model["subnets"],
        )
      )
      #! OPT. Process the results
      # Actions return events that contain information about what happened
      for event in events:
        # Always use logging instead of print() statements
        # This ensures output goes to the correct log files and can be filtered
        # Can use .error(), .warning(), .debug() as needed
        self.logger.info(f"Scan results: \n{event}")
      

    # Returns True when attack is complete, returns false if more steps can be executed
    async def step(self) -> bool:
        """
        The main execution method for your strategy.
        
        This method is called repeatedly until it returns True (indicating the attack is complete).
        Each call to step() should perform one logical unit of attack work.
        
        Returns:
            bool: True if the attack is complete, False if more steps should be executed
            
        Design patterns for step():
        - Single action per step: Each step() call performs one action (scan, exploit, etc.)
        - Multi-step attacks: Use instance variables to track progress through attack phases
        - Conditional logic: Check environment state to decide next actions
        - Error handling: Handle failed actions gracefully and continue or abort as appropriate
        """
        
        self.collect_telemetry()  #! STEP 1: Gather information about the current environment
        world_model = self.update_world_model()  #! STEP 2: Update world model based on collected telemetry
        self.planner(world_model)  #! STEP 3: Plan your next action based
        await self.act(world_model)           #! STEP 4: Execute your chosen action
        

        #! STEP 5: Determine if the attack should continue
        # This example uses a simple step counter, but you might check:
        # - Whether objectives have been met
        # - If there are more targets to attack
        # - If previous actions were successful
        # - If time/resource limits have been reached
        if self.cur_step >= self.total_steps:
            self.logger.info("Attack strategy completed successfully")
            return True  # Attack is complete
        else:
            self.cur_step += 1
            self.logger.info(f"Completed step {self.cur_step}/{self.total_steps}")
            return False  # More steps to execute