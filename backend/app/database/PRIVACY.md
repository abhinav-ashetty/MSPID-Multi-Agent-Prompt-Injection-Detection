# Privacy Considerations for AIShield Defender Persistence Layer

## Prompt Storage and Sensitivity

The AIShield persistence layer stores original assessment prompts and generated simulation prompts. Simulation results can also store the Target response and matched protected-canary values. These values may contain sensitive information, including but not limited to:

- Personally identifiable information (PII)
- Proprietary business information
- Authentication credentials or tokens
- Confidential communications
- Other sensitive data that users may not intend to persist

## Production Deployment Recommendations

For production deployments, consider the following privacy protections:

### 1. Encryption
- Enable database-level encryption for the SQLite file
- Consider using encrypted filesystems or storage solutions
- Implement application-level encryption for highly sensitive fields

### 2. Access Controls
- Restrict file system permissions on the database file
- Implement role-based access control for database access
- Audit database access and query logs

### 3. Data Minimization
- Consider storing only hashed or anonymized versions of prompts when full retention is not required
- Implement prompt truncation to store only relevant portions for security analysis
- Use data masking techniques for known sensitive patterns

### 4. Retention Policies
- Implement automated data deletion based on retention requirements
- Allow users to request deletion of their data (right to be forgotten)
- Archive old data to secure, access-controlled storage

### 5. Secure Configuration
- Ensure the database file is not accessible via web server
- Use environment variables or secure secrets management for configuration
- Regularly update and patch dependencies

## Current Prototype Limitations

This prototype implementation uses local SQLite with the following characteristics:

- **Storage Location**: `backend/app/data/aishield.db` (relative to application root)
- **Access**: File-based access to SQLite database
- **Encryption**: None (plain text SQLite file)
- **Access Controls**: Dependent on file system permissions
- **Retention**: Infinite (data persists until manually deleted)

## Stored Data Fields

The persistence layer stores the following fields from each security assessment:

1. **Assessment Prompt**: The exact text submitted for analysis (potentially sensitive)
2. **Simulation Prompt and Output**: Generated attack prompt, Target response, Defender decision, canary matches, success/outcome, and errors
3. **Assessment Results**: Decision, scores, confidence, and reasoning
4. **Metadata**: Timestamps and optional detector details

Simulation history/detail routes and assessment history/detail routes currently have no authentication or authorization. Keep the prototype local and do not expose these endpoints or the SQLite file to untrusted users.

## Compliance Considerations

Organizations using this persistence layer should consider applicable regulations:

- GDPR (General Data Protection Regulation) for EU data subjects
- CCPA (California Consumer Privacy Act) for California residents
- HIPAA (Health Insurance Portability and Accountability Act) for health information
- SOC 2, ISO 27001, or other industry-specific standards

## Recommendations for Secure Usage

1. **Environment Isolation**: Run the defender service in a secured, isolated environment
2. **Network Security**: Ensure the host system is properly firewalled and monitored
3. **Backup Security**: Encrypt backups and apply same access controls to backup files
4. **Monitoring**: Implement logging and alerting for suspicious database access patterns
5. **Regular Review**: Periodically review stored data and delete what is no longer needed

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Organizations are responsible for ensuring their use of this software complies with all applicable laws, regulations, and organizational policies regarding data protection and privacy.

\n
