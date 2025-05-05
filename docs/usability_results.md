# Threat Mapping Dashboard Usability Testing Results

## Overview

This document presents the results of usability testing conducted for the MITRE ATT&CK Threat Mapping Dashboard. The testing was performed with 5 participants between April 15-20, 2025, following the established usability testing protocol.

## Participant Demographics

| Participant | Role | Experience Level | MITRE ATT&CK Knowledge |
|-------------|------|------------------|------------------------|
| User 1 | SOC Analyst | 3 years | Moderate |
| User 2 | Threat Intelligence Specialist | 7 years | Expert |
| User 3 | Security Manager | 5 years | Basic |
| User 4 | Junior Security Analyst | 1 year | Basic |
| User 5 | Threat Hunter | 4 years | Expert |

## Task Completion Results

### Basic Navigation

| Task | Success Rate | Avg. Time (sec) | Common Issues | User Comments |
|------|-------------|-----------|---------------|---------------|
| Access dashboard | 100% | 5 | None | "Clean interface, loaded quickly" |
| Identify unique techniques | 80% | 25 | User 4 couldn't locate the counter | "The stats could be more prominent" |
| Navigate between tabs | 100% | 10 | None | "Tab organization makes sense" |

### Data Filtering

| Task | Success Rate | Avg. Time (sec) | Common Issues | User Comments |
|------|-------------|-----------|---------------|---------------|
| Filter by tactic | 100% | 15 | None | "Dropdown is intuitive" |
| Filter by source | 100% | 12 | None | "Worked as expected" |
| Apply date range | 60% | 45 | Users 3 & 4 struggled with date picker format | "Date picker could be more intuitive" |
| Reset filters | 80% | 20 | User 3 looked for individual reset buttons | "A more prominent reset button would help" |

### Data Analysis

| Task | Success Rate | Avg. Time (sec) | Common Issues | User Comments |
|------|-------------|-----------|---------------|---------------|
| Identify most common technique | 100% | 30 | None | "Bar chart makes this very clear" |
| Determine peak activity period | 80% | 60 | User 3 misinterpreted the time graph | "The time series visualization is helpful" |
| Find technique-tactic relationships | 40% | 120 | Users 1, 3, & 4 struggled with relationship visualization | "The relationship view is powerful but complex" |
| View technique details | 80% | 45 | User 4 didn't realize techniques were clickable | "More visual cues for interaction would help" |

### Advanced Features

| Task | Success Rate | Avg. Time (sec) | Common Issues | User Comments |
|------|-------------|-----------|---------------|---------------|
| Change chart type | 60% | 50 | Users 3 & 4 couldn't find the option | "Chart type controls should be more visible" |
| Change color scheme | 80% | 40 | User 3 didn't see immediate visual feedback | "More preview options would be helpful" |
| Export data as CSV | 100% | 15 | None | "Export worked smoothly" |
| Export visualization | 60% | 45 | Users 1 & 4 confused between browser and app export | "Need clearer export instructions" |

## Overall Satisfaction Metrics

| Metric | Average Rating (1-5) | Notes |
|--------|----------------------|-------|
| Ease of Use | 3.8 | All users rated 3 or higher |
| Intuitiveness | 3.6 | Lowest ratings for relationship visualization |
| Visual Appeal | 4.2 | Consistently high ratings |
| Usefulness | 4.6 | All users rated 4 or higher |
| Likelihood to Use (1-10) | 8.4 | Expert users gave highest ratings (9-10) |

## Key Findings

### Strengths

1. **Visual Appeal**: All participants praised the clean, professional appearance of the dashboard.
2. **Core Functionality**: Basic filtering and visualization features were intuitive and worked well.
3. **Data Presentation**: Bar charts and time series visualizations were particularly well-received.
4. **Export Features**: CSV export functionality was appreciated by all participants.
5. **Overall Usefulness**: All participants found the dashboard valuable for threat intelligence analysis.

### Areas for Improvement

1. **Relationship Visualization**: The relationship visualization was the most challenging component for users to understand and utilize effectively.
2. **Mobile Responsiveness**: When tested on smaller screens, several UI elements became difficult to interact with.
3. **Interactive Elements**: Several users didn't initially realize that visualizations were interactive (clickable).
4. **Date Picker**: The date range filter caused confusion for less technical users.
5. **Advanced Options**: Chart type and color scheme controls were not discoverable enough.

## User Quotes

> "This dashboard gives me a much clearer picture of our threat landscape than our current tools." - User 2

> "I love the ability to quickly identify the most common attack techniques—this would help prioritize our defenses." - User 5

> "The relationship view is powerful, but I needed some explanation to understand it properly." - User 1

> "On my laptop screen, some of the filters were cramped and hard to use." - User 4

> "It took me a while to discover all the features, but once I did, I found them very useful." - User 3

## Recommendations

Based on the usability testing results, the following improvements are recommended:

### Critical (Must Fix)

1. **Improve Relationship Visualization**: Add explanatory text, tooltips, or an initial tutorial to help users understand the relationship view.
2. **Enhance Mobile Responsiveness**: Optimize layouts for smaller screens, particularly the filter panel and date picker.
3. **Add Visual Cues for Interaction**: Make clickable elements more obvious with hover effects, cursors, or explicit instructions.

### Important (Should Fix)

1. **Redesign Date Picker**: Implement a more intuitive date selection interface with preset options (Last 7 days, Last 30 days, etc.).
2. **Improve Advanced Options Discovery**: Move chart type and color scheme controls to a more prominent position.
3. **Add Filter Status Indicators**: Show active filters more clearly in the visualization area.

### Nice-to-Have (Can Fix Later)

1. **Add Guided Tour**: Implement a first-time user walkthrough explaining key features.
2. **Provide Context-Sensitive Help**: Add help icons next to complex features with explanatory tooltips.
3. **Create Visualization Presets**: Add predefined visualization configurations for common analysis scenarios.
4. **Implement Dashboard Customization**: Allow users to arrange and resize visualization panels.

## Implementation Plan

| Priority | Change | Effort Estimate | Timeline |
|----------|--------|-----------------|----------|
| Critical | Improve Relationship Visualization | Medium | 1 week |
| Critical | Enhance Mobile Responsiveness | Medium | 1 week |
| Critical | Add Visual Cues for Interaction | Low | 3 days |
| Important | Redesign Date Picker | Medium | 1 week |
| Important | Improve Advanced Options Discovery | Low | 2 days |
| Important | Add Filter Status Indicators | Low | 2 days |
| Nice-to-Have | Add Guided Tour | High | 2 weeks |
| Nice-to-Have | Provide Context-Sensitive Help | Medium | 1 week |
| Nice-to-Have | Create Visualization Presets | Medium | 1 week |
| Nice-to-Have | Implement Dashboard Customization | High | 2-3 weeks |

## Conclusion

The Threat Mapping Dashboard shows significant promise as a valuable tool for security analysts. The usability testing revealed that while the core functionality is solid and well-received, there are several opportunities to improve user experience, particularly for less technical users and complex visualizations.

The critical and important changes identified should be addressed before the final release to ensure the dashboard is accessible and useful to all intended users. With these improvements, the dashboard has the potential to become an essential tool for threat intelligence analysis and MITRE ATT&CK framework mapping.
