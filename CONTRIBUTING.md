# Contributing to Packer

Thanks for wanting to help make Packer better! This guide will show you how to get started.

## Quick Start

1. **Fork the project** on GitHub
2. **Clone your fork** to your computer
3. **Make your changes** 
4. **Test everything works**
5. **Submit a pull request**

## Setting Up Your Development Environment

### What You Need

- Rust (latest stable version)
- Git
- A text editor or IDE
- Basic knowledge of Rust programming

### Getting the Code

```bash
# Fork the repo on GitHub first, then:
git clone https://github.com/YOUR-USERNAME/packer.git
cd packer

# Add the original repo as upstream
git remote add upstream https://github.com/d0mkaaa/packer.git
```

### Building and Testing

```bash
# Build the project
cargo build

# Run tests
cargo test

# Check for code style issues
cargo clippy

# Format your code
cargo fmt
```

## Making Changes

### Before You Start

- Check if someone else is already working on the same thing
- Open an issue to discuss big changes first
- Keep changes focused - one feature per pull request

### Writing Good Code

**Keep it simple**: Write code that's easy to read and understand.

**Add comments**: Explain why you did something, not just what you did.

**Test your changes**: Make sure everything still works after your changes.

**Follow the style**: Use `cargo fmt` to format your code properly.

### Commit Messages

Write clear commit messages that explain what you changed:

```
Good: "Fix broken pipe error in search command"
Bad: "fix bug"
```

## Types of Contributions

### Bug Fixes
Found something broken? Great! Please:
- Describe what's wrong
- Show how to reproduce the problem
- Include error messages if any

### New Features
Want to add something cool? Awesome! Please:
- Explain why it would be useful
- Keep it simple and focused
- Make sure it fits with the project's goals

### Documentation
Help make things clearer by:
- Fixing typos
- Adding examples
- Improving explanations
- Updating outdated info

### Code Cleanup
Help keep the code tidy by:
- Removing unused code
- Fixing compiler warnings
- Improving variable names
- Adding missing tests

## Pull Request Process

### 1. Create a Branch
```bash
git checkout -b fix-search-bug
```

### 2. Make Your Changes
- Write the code
- Add tests if needed
- Update documentation

### 3. Test Everything
```bash
cargo test
cargo clippy
cargo fmt --check
```

### 4. Commit Your Changes
```bash
git add .
git commit -m "Fix search command pipe handling"
```

### 5. Push and Create PR
```bash
git push origin fix-search-bug
```

Then go to GitHub and create a pull request.

### 6. Wait for Review
- Be patient - reviews take time
- Be open to feedback
- Make requested changes if needed

## Code Style Guidelines

### Rust Style
- Use `cargo fmt` to format code
- Follow standard Rust naming conventions
- Keep functions small and focused
- Use meaningful variable names

### Error Handling
- Use `Result` types for operations that can fail
- Provide helpful error messages
- Don't panic unless absolutely necessary

### Testing
- Write tests for new features
- Test edge cases and error conditions
- Keep tests simple and clear

## Getting Help

Stuck? No problem! Here's how to get help:

1. **Check existing issues** - someone might have asked the same question
2. **Read the documentation** - it might have the answer
3. **Ask in a new issue** - we're happy to help!

## Code of Conduct

### Be Nice
- Be respectful to everyone
- Help newcomers learn
- Give constructive feedback
- Assume good intentions

### Be Professional
- Keep discussions focused on the code
- Avoid controversial topics
- Use clear, professional language

## Project Structure

Understanding how the code is organized:

```
src/
├── main.rs          # Command line interface
├── lib.rs           # Main library entry point
├── config.rs        # Configuration handling
├── package.rs       # Package management
├── repository.rs    # Repository operations
├── storage.rs       # Data storage
├── resolver.rs      # Dependency resolution
├── utils.rs         # Helper functions
└── error.rs         # Error types
```

## Security

If you find a security issue:
1. **Don't** open a public issue
2. **Do** email the maintainers privately
3. Give us time to fix it before telling others

## Questions?

If you have questions about contributing:
- Open an issue with the "question" label
- Check if your question is already answered in existing issues
- Be specific about what you're trying to do

## Recognition

All contributors will be:
- Added to the contributors list
- Mentioned in release notes for significant contributions
- Given credit in commit history

Thanks for helping make Packer better! 🚀 