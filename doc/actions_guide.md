# TraceBack Code Actions & Suggestions - Quick Start Guide

## Overview

TraceBack's code actions and systematic suggestion system provides intelligent, context-aware recommendations for improving your code. The system analyzes complexity, security patterns, performance characteristics, and code quality.

## Quick Setup

```lua
require('traceback').setup({
  -- Enable all suggestion features
  actions = {
    enable_smart_suggestions = true,
    suggestion_engine = {
      enable_complexity_analysis = true,
      enable_pattern_detection = true,
      enable_security_suggestions = true,
      enable_performance_hints = true,
      suggestion_confidence_threshold = 0.7
    }
  }
})
```

## Basic Workflow

### 1. Automatic Detection
- Open any code file
- TraceBack automatically scans and highlights issues with lenses
- Security issues appear with 🔒 icon
- Complexity issues appear with 💡 icon
- Performance issues appear with ⚡ icon

### 2. View Actions at Cursor
```
<Leader>ta   -- Show actions for annotation at cursor
```
Or use command:
```
:TracebackActions
```

### 3. Get Buffer-wide Suggestions
```
<Leader>ts   -- Show improvement suggestions for entire buffer
```
Or use command:
```
:TracebackSuggestBuffer
```

### 4. Get Function-specific Suggestions
```
<Leader>tF   -- Show suggestions for current function
```
Or use command:
```
:TracebackSuggestFunction
```

## Action Types

### Security Actions
- **Add to Allowlist**: Suppress false positive security warnings
- **Apply Security Fix**: Automatically replace with secure alternative
- **Show Security Docs**: Open relevant security documentation
- **Copy Secure Snippet**: Copy secure code alternative to clipboard

### Refactoring Actions
- **Extract Method**: Get guidance on breaking down complex functions
- **Reduce Complexity**: Suggestions for simplifying code structure
- **Parameter Object**: Convert many parameters to config object
- **Guard Clauses**: Use early returns to reduce nesting

### Performance Actions
- **Apply Optimization**: Replace with more efficient code
- **Show Benchmark**: Compare performance characteristics
- **Cache Variables**: Identify repeated expensive operations
- **Loop Optimization**: Improve iteration patterns

### Code Quality Actions
- **Modernize Code**: Update to modern language features
- **Remove Debug Code**: Clean up debug statements
- **Improve Readability**: Make code more readable and idiomatic
- **Add Documentation**: Suggest documentation improvements

## Example Usage

### Security Issue
```lua
-- This will trigger a security suggestion
loadstring(user_input)()
```
1. Position cursor on `loadstring`
2. Press `<Leader>ta`
3. Select "Apply Security Fix"
4. Code gets replaced with safer alternative

### Complex Function
```lua
-- This will trigger refactoring suggestions
function complex_function(a, b, c, d, e, f, g)
  if a then
    if b then
      if c then
        -- deep nesting...
      end
    end
  end
end
```
1. Position cursor inside function
2. Press `<Leader>tF`
3. See suggestions for complexity reduction
4. Get step-by-step refactoring guidance

### Performance Issue
```lua
-- This will trigger performance suggestions (in a loop)
for i = 1, 1000 do
  result = result .. data[i]  -- Inefficient concatenation
end
```
1. Position cursor on concatenation
2. Press `<Leader>ta`
3. Select "Apply Optimization"
4. Get suggestion for table.concat or other efficient method

## Advanced Features

### Confidence Scoring
- Each suggestion shows confidence percentage
- Higher confidence = more reliable suggestion
- Threshold configurable (default 70%)

### Impact Assessment
- **Security**: Critical security vulnerabilities
- **Performance**: Speed and memory optimizations
- **Maintainability**: Code structure improvements
- **Readability**: Code clarity enhancements

### Language-Specific Analysis
- **Lua**: Idiomatic patterns, metatables, coroutines
- **Python**: List comprehensions, generators, type hints
- **JavaScript**: Modern ES features, async patterns
- **C/C++**: Memory safety, buffer overflows
- **Go**: Concurrency patterns, error handling

### Context Awareness
- Function scope analysis
- Loop context detection
- Variable usage patterns
- Code complexity metrics

## Configuration Options

```lua
require('traceback').setup({
  actions = {
    suggestion_engine = {
      -- Analysis modules
      enable_complexity_analysis = true,
      enable_pattern_detection = true,
      enable_security_suggestions = true,
      enable_performance_hints = true,
      
      -- Filtering
      suggestion_confidence_threshold = 0.7,  -- 0.0 to 1.0
      max_suggestions_per_scan = 10,
      
      -- Performance
      scan_timeout_ms = 1000
    },
    
    -- Keymaps
    keymaps = {
      show_actions = '<Leader>ta',
      quick_fix = '<Leader>tf',
      explain = '<Leader>te',
      allowlist = '<Leader>tw',
      suggest_improvements = '<Leader>ts',
      suggest_function = '<Leader>tF'
    }
  }
})
```

## Tips

1. **Start Small**: Begin with `<Leader>ta` on highlighted issues
2. **Use Function Scope**: `<Leader>tF` gives focused suggestions
3. **Review Explanations**: `<Leader>te` provides detailed information
4. **Manage False Positives**: Use allowlisting for irrelevant warnings
5. **Learn Gradually**: Suggestions include educational content

## Troubleshooting

### No Suggestions Appearing
- Check if `enable_smart_suggestions = true`
- Verify file type is supported
- Try lowering `suggestion_confidence_threshold`

### Too Many Suggestions
- Increase `suggestion_confidence_threshold`
- Use allowlisting for false positives
- Decrease `max_suggestions_per_scan`

### Performance Issues
- Reduce `scan_timeout_ms`
- Disable heavy analysis modules temporarily
- Use function-scope analysis instead of buffer-wide

## Demo File

See `examples/demo_suggestions.lua` for examples of code patterns that trigger different types of suggestions.

## Contributing

The suggestion system is extensible:
- Add new pattern detection rules
- Contribute language-specific analyzers
- Improve confidence scoring algorithms
- Add new action types

For more information, see the main README and contributing guidelines.
