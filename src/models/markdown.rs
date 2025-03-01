use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::Result;

/// Represents a markdown document with sections and content
pub struct MarkdownDocument {
    title: String,
    sections: Vec<MarkdownSection>,
}

/// Represents a section in a markdown document
pub struct MarkdownSection {
    heading: String,
    level: usize,
    content: String,
    subsections: Vec<MarkdownSection>,
}

/// Represents a table in markdown format
pub struct MarkdownTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl MarkdownDocument {
    /// Create a new markdown document with a title
    pub fn new(title: &str) -> Self {
        MarkdownDocument {
            title: title.to_string(),
            sections: Vec::new(),
        }
    }

    /// Add a section to the document
    pub fn add_section(&mut self, section: MarkdownSection) {
        self.sections.push(section);
    }

    /// Generate the markdown string representation of the document
    pub fn to_string(&self) -> String {
        let mut output = format!("# {}\n\n", self.title);
        
        for section in &self.sections {
            output.push_str(&section.to_string());
            output.push_str("\n\n");
        }
        
        output
    }

    /// Save the markdown document to a file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_string())?;
        Ok(())
    }
}

impl MarkdownSection {
    /// Create a new markdown section with a heading
    pub fn new(heading: &str, level: usize) -> Self {
        MarkdownSection {
            heading: heading.to_string(),
            level,
            content: String::new(),
            subsections: Vec::new(),
        }
    }

    /// Add content to the section
    pub fn add_content(&mut self, content: &str) {
        if !self.content.is_empty() {
            self.content.push_str("\n\n");
        }
        self.content.push_str(content);
    }

    /// Add a code block to the section
    pub fn add_code_block(&mut self, code: &str, language: &str) {
        let code_block = format!("```{}\n{}\n```", language, code);
        self.add_content(&code_block);
    }

    /// Add a subsection to the section
    pub fn add_subsection(&mut self, subsection: MarkdownSection) {
        self.subsections.push(subsection);
    }

    /// Generate the markdown string representation of the section
    pub fn to_string(&self) -> String {
        let heading_prefix = "#".repeat(self.level);
        let mut output = format!("{} {}\n\n", heading_prefix, self.heading);
        
        if !self.content.is_empty() {
            output.push_str(&self.content);
            output.push_str("\n\n");
        }
        
        for subsection in &self.subsections {
            output.push_str(&subsection.to_string());
            output.push_str("\n\n");
        }
        
        output.trim_end().to_string()
    }
}

impl MarkdownTable {
    /// Create a new markdown table with headers
    pub fn new(headers: Vec<String>) -> Self {
        MarkdownTable {
            headers,
            rows: Vec::new(),
        }
    }

    /// Add a row to the table
    pub fn add_row(&mut self, row: Vec<String>) {
        if row.len() != self.headers.len() {
            panic!("Row length does not match header length");
        }
        self.rows.push(row);
    }

    /// Generate the markdown string representation of the table
    pub fn to_string(&self) -> String {
        if self.headers.is_empty() {
            return String::new();
        }

        let mut output = String::new();
        
        // Add headers
        output.push('|');
        for header in &self.headers {
            output.push_str(&format!(" {} |", header));
        }
        output.push('\n');
        
        // Add separator
        output.push('|');
        for _ in &self.headers {
            output.push_str(" --- |");
        }
        output.push('\n');
        
        // Add rows
        for row in &self.rows {
            output.push('|');
            for cell in row {
                output.push_str(&format!(" {} |", cell));
            }
            output.push('\n');
        }
        
        output
    }
}

/// Helper function to create a markdown report from analysis results
pub fn create_analysis_report(
    program_name: &str,
    findings: HashMap<PathBuf, Vec<Finding>>,
    output_path: Option<&Path>,
) -> Result<String> {
    let mut doc = MarkdownDocument::new(&format!("Solana Fender Analysis: {}", program_name));
    
    // Add summary section
    let mut summary = MarkdownSection::new("Summary", 2);
    let total_findings = findings.values().map(|v| v.len()).sum::<usize>();
    summary.add_content(&format!("Total findings: {}", total_findings));
    
    // Add findings table
    if total_findings > 0 {
        let mut table = MarkdownTable::new(vec![
            "Severity".to_string(),
            "Count".to_string(),
        ]);
        
        // Count findings by severity
        let mut severity_counts: HashMap<&str, usize> = HashMap::new();
        for file_findings in findings.values() {
            for finding in file_findings {
                *severity_counts.entry(&finding.severity).or_insert(0) += 1;
            }
        }
        
        // Add rows to table
        for (severity, count) in severity_counts {
            table.add_row(vec![
                severity.to_string(),
                count.to_string(),
            ]);
        }
        
        summary.add_content(&table.to_string());
    }
    
    doc.add_section(summary);
    
    // Add detailed findings section
    let mut details = MarkdownSection::new("Detailed Findings", 2);
    
    if total_findings == 0 {
        details.add_content("No issues found.");
    } else {
        for (file_path, file_findings) in findings {
            let file_name = file_path.to_string_lossy();
            let mut file_section = MarkdownSection::new(&format!("File: {}", file_name), 3);
            
            for finding in file_findings {
                let mut finding_section = MarkdownSection::new(&finding.title, 4);
                finding_section.add_content(&format!("**Severity**: {}", finding.severity));
                finding_section.add_content(&format!("**Location**: Line {}", finding.line));
                finding_section.add_content(&format!("**Description**: {}", finding.description));
                
                if let Some(code) = &finding.code_snippet {
                    finding_section.add_code_block(code, "rust");
                }
                
                if let Some(recommendation) = &finding.recommendation {
                    finding_section.add_content(&format!("**Recommendation**: {}", recommendation));
                }
                
                file_section.add_subsection(finding_section);
            }
            
            details.add_subsection(file_section);
        }
    }
    
    doc.add_section(details);
    
    // Save to file if output path is provided
    if let Some(path) = output_path {
        doc.save_to_file(path)?;
    }
    
    Ok(doc.to_string())
}

/// Represents a finding in the analysis
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub line: usize,
    pub description: String,
    pub code_snippet: Option<String>,
    pub recommendation: Option<String>,
}

impl Finding {
    pub fn new(
        title: &str,
        severity: &str,
        line: usize,
        description: &str,
    ) -> Self {
        Finding {
            title: title.to_string(),
            severity: severity.to_string(),
            line,
            description: description.to_string(),
            code_snippet: None,
            recommendation: None,
        }
    }
} 