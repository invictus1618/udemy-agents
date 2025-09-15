from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class Nmap():
    """Nmap crew"""

    agents: List[BaseAgent]
    tasks: List[Task]

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    
    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def security_manager(self) -> Agent:
        return Agent(
            config=self.agents_config['security_manager'],  # type: ignore[index]
            verbose=True,
        )

    @agent
    def nmap_scanner(self) -> Agent:
        return Agent(
            config=self.agents_config['nmap_scanner'],  # type: ignore[index]
            verbose=True,
        )

    @agent
    def kali_command(self) -> Agent:
        return Agent(
            config=self.agents_config['kali_command'],  # type: ignore[index]
            verbose=True,
        )

    @agent
    def nmap_results_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['nmap_results_analyst'],  # type: ignore[index]
            verbose=True,
        )

    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def results_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['results_analysis_task'],  # type: ignore[index]
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Nmap crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents,  # Automatically created by the @agent decorator
            tasks=self.tasks,  # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=False,
        )
