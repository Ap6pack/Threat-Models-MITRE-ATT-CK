# Threat Mapping Dashboard Usability Testing Protocol

## Overview

This document outlines the usability testing protocol for the MITRE ATT&CK Threat Mapping Dashboard. The purpose of this testing is to evaluate the dashboard's usability, identify any issues, and gather feedback for improvements.

## Test Participants

Recruit 3-5 participants with the following characteristics:
- Security analysts or professionals with knowledge of threat intelligence
- Varying levels of technical expertise (junior to senior)
- Mixture of experience with MITRE ATT&CK framework (novice to expert)
- Different departments/roles if possible (SOC analysts, threat hunters, security managers)

## Testing Environment

- Prepare a testing environment with sample threat data
- Ensure the dashboard is running with all features enabled
- Set up screen recording software (with participant permission)
- Prepare a quiet room with minimal distractions

## Test Tasks

Participants will be asked to complete the following tasks:

1. **Basic Navigation**
   - Access the dashboard
   - Identify the number of unique techniques in the dataset
   - Navigate between different visualization tabs

2. **Data Filtering**
   - Filter data to show only techniques from the "Defense Evasion" tactic
   - Filter data to show only threats from a specific source
   - Apply a date range filter for the last 30 days
   - Reset all filters

3. **Data Analysis**
   - Identify the most common technique in the dataset
   - Determine when threat activity was highest (using the Timeline tab)
   - Find relationships between specific techniques and tactics
   - Examine detailed information for a specific technique

4. **Advanced Features**
   - Change the chart type from bar chart to treemap
   - Change the color scheme
   - Export filtered data as CSV
   - Export a visualization as PNG

## Data Collection

Collect the following data during testing:

1. **Task Completion Metrics**
   - Success/failure for each task
   - Time to complete each task
   - Number of errors or mistaken actions

2. **Observational Data**
   - Navigation patterns
   - Points of confusion
   - Workarounds attempted

3. **Participant Feedback**
   - Think-aloud commentary during tasks
   - Post-task ratings (1-5 scale) for:
     - Ease of use
     - Intuitiveness
     - Visual appeal
     - Usefulness of information
   - Post-test interview questions

## Post-Test Interview Questions

1. What aspects of the dashboard did you find most useful?
2. What aspects were most confusing or difficult to use?
3. What features would you like to see added to the dashboard?
4. How would this dashboard fit into your current workflow?
5. On a scale of 1-10, how likely would you be to use this dashboard regularly?
6. How does this compare to other visualization tools you've used for threat intelligence?

## Analysis and Reporting

After testing is complete:

1. Compile all metrics and feedback
2. Identify common patterns and issues
3. Prioritize issues based on:
   - Severity (how much it impedes usage)
   - Frequency (how many users encountered it)
   - Impact (how it affects core functionality)
4. Create a summary report with:
   - Key findings
   - Prioritized list of issues
   - Recommended changes
   - Timelines for implementation

## Implementation Plan

Based on the testing results, create an implementation plan that:

1. Categorizes changes as:
   - Critical (must fix)
   - Important (should fix)
   - Nice-to-have (can fix later)
2. Estimates effort required for each change
3. Proposes a timeline for implementing changes
4. Sets metrics for measuring improvement

## Follow-up Testing

After implementing high-priority changes:

1. Conduct follow-up testing with a subset of original participants
2. Measure improvement in task completion metrics
3. Gather feedback on the implemented changes
4. Document lessons learned for future development

## Sample Usability Testing Results Template

| Task | Success Rate | Avg. Time | Common Issues | User Comments |
|------|-------------|-----------|---------------|---------------|
| Basic Navigation | | | | |
| Data Filtering | | | | |
| Data Analysis | | | | |
| Advanced Features | | | | |

## Overall Satisfaction Metrics

| Metric | Average Rating (1-5) | Notes |
|--------|----------------------|-------|
| Ease of Use | | |
| Intuitiveness | | |
| Visual Appeal | | |
| Usefulness | | |
| Likelihood to Use (1-10) | | |
