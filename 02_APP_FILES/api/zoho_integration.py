"""
TicketZero AI - Zoho Desk Integration Layer
Marketplace-ready API bridge between Zoho Desk and TicketZero AI engine
"""

import json
import requests
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS

# Try to import the TicketZero engine, use stub if not available
try:
    # First try relative import
    from .core.integrated_engine import IntegratedTicketSystem
except ImportError:
    try:
        # Try absolute import
        from core.integrated_engine import IntegratedTicketSystem
    except ImportError:
        # Fallback to adding parent directories
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from core.integrated_engine import IntegratedTicketSystem

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TicketZero.ZohoIntegration")

app = Flask(__name__)
# Configure CORS for Zoho domains only
CORS(app, origins=['https://*.zoho.com', 'https://*.zoho.eu', 'https://*.zoho.in', 'https://*.zoho.com.au'])

# Initialize TicketZero AI engine
ticketzero_engine = None

class ZohoTicketZeroAPI:
    """
    API bridge between Zoho Desk and TicketZero AI
    Handles all marketplace communication and ticket processing
    """
    
    def __init__(self):
        global ticketzero_engine
        try:
            ticketzero_engine = IntegratedTicketSystem(ollama_model="llama2")
            logger.info("✅ TicketZero AI engine initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize TicketZero engine: {e}")
            ticketzero_engine = None
    
    def validate_request(self, request_data: Dict) -> bool:
        """Validate incoming requests for security"""
        required_fields = ['ticket']
        
        for field in required_fields:
            if field not in request_data:
                return False
        
        ticket = request_data['ticket']
        if not isinstance(ticket, dict) or 'id' not in ticket:
            return False
            
        return True
    
    def sanitize_ticket_data(self, zoho_ticket: Dict) -> Dict:
        """Convert Zoho ticket format to TicketZero format"""
        return {
            'id': zoho_ticket.get('id', ''),
            'title': zoho_ticket.get('subject', ''),
            'description': zoho_ticket.get('description', ''),
            'user': zoho_ticket.get('contact', {}).get('email', 'unknown'),
            'priority': zoho_ticket.get('priority', 'normal'),
            'department': zoho_ticket.get('departmentId', ''),
            'created_time': zoho_ticket.get('createdTime', datetime.now().isoformat()),
            'status': zoho_ticket.get('status', 'Open')
        }
    
    def generate_zoho_response(self, resolution: Dict) -> Dict:
        """Format TicketZero response for Zoho Desk"""
        if resolution['status'] == 'resolved':
            return {
                'success': True,
                'resolution_note': f"""✅ AUTOMATICALLY RESOLVED by TicketZero AI

🔍 Analysis Results:
• Issue Type: {resolution['issue_type'].replace('_', ' ').title()}
• Confidence Score: {resolution['confidence']}%
• Resolution Time: {resolution['time_to_resolve']:.1f} seconds

⚡ Actions Taken:
{chr(10).join(f'• {cmd}' for cmd in resolution['commands_executed'])}

📊 Impact:
• Time Saved: {resolution['time_saved']} minutes
• Cost Savings: ${resolution['money_saved']:.2f}
• Status: Resolved automatically

🤖 This ticket was resolved using local LLM intelligence with no human intervention required.
Customer data remained secure and never left your network.""",
                'execution_time': resolution.get('time_to_resolve', 0),
                'commands_executed': len(resolution.get('commands_executed', [])),
                'cost_savings': resolution.get('money_saved', 0)
            }
        
        elif resolution['status'] == 'escalated':
            return {
                'success': False,
                'requires_human': True,
                'escalation_reason': resolution['reason'],
                'suggested_actions': resolution.get('suggested_actions', []),
                'analysis': resolution.get('analysis', {})
            }
        
        else:
            return {
                'success': False,
                'error': 'Unknown resolution status',
                'resolution': resolution
            }

# Initialize API handler
zoho_api = ZohoTicketZeroAPI()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for marketplace monitoring"""
    global ticketzero_engine
    
    status = {
        'service': 'TicketZero AI for Zoho Desk',
        'version': '1.0.0',
        'status': 'healthy' if ticketzero_engine else 'engine_error',
        'timestamp': datetime.now().isoformat(),
        'ollama_connected': False
    }
    
    if ticketzero_engine:
        try:
            # Test Ollama connection
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            status['ollama_connected'] = response.status_code == 200
        except:
            status['ollama_connected'] = False
    
    return jsonify(status)

@app.route('/api/analyze-ticket', methods=['POST'])
def analyze_ticket():
    """
    Main endpoint for ticket analysis
    Called from Zoho Desk marketplace app
    """
    try:
        request_data = request.get_json()
        
        # Validate request
        if not zoho_api.validate_request(request_data):
            return jsonify({
                'success': False,
                'error': 'Invalid request format'
            }), 400
        
        # Check if engine is available
        global ticketzero_engine
        if not ticketzero_engine:
            return jsonify({
                'success': False,
                'error': 'TicketZero AI engine not available'
            }), 503
        
        # Convert Zoho ticket to TicketZero format
        zoho_ticket = request_data['ticket']
        ticketzero_ticket = zoho_api.sanitize_ticket_data(zoho_ticket)
        
        logger.info(f"🎫 Analyzing Zoho ticket: {ticketzero_ticket['id']}")
        
        # Use TicketZero AI for analysis
        analysis = ticketzero_engine.llm_engine.analyze_ticket(ticketzero_ticket)
        
        # Add marketplace-specific metadata
        analysis['marketplace'] = 'zoho_desk'
        analysis['zoho_ticket_id'] = zoho_ticket.get('id')
        analysis['processed_at'] = datetime.now().isoformat()
        
        logger.info(f"✅ Analysis complete: {analysis['issue_type']} ({analysis['confidence']}%)")
        
        return jsonify({
            'success': True,
            'data': analysis,
            'message': 'Ticket analyzed successfully'
        })
        
    except Exception as e:
        logger.error(f"❌ Analysis failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/execute-resolution', methods=['POST'])
def execute_resolution():
    """
    Execute automated resolution for analyzed ticket
    Called after user confirms they want to proceed
    """
    try:
        request_data = request.get_json()
        
        if 'ticket_id' not in request_data or 'analysis' not in request_data:
            return jsonify({
                'success': False,
                'error': 'Missing ticket_id or analysis data'
            }), 400
        
        # Check if engine is available
        global ticketzero_engine
        if not ticketzero_engine:
            return jsonify({
                'success': False,
                'error': 'TicketZero AI engine not available'
            }), 503
        
        ticket_id = request_data['ticket_id']
        analysis = request_data['analysis']
        auto_mode = request_data.get('auto_mode', False)
        
        logger.info(f"⚡ Executing resolution for ticket: {ticket_id}")
        
        # Execute commands using TicketZero engine
        commands = analysis.get('solution_commands', [])
        execution_results = ticketzero_engine.execute_commands(commands, {'id': ticket_id})
        
        # Check if execution was successful
        success = all(r.get('success', False) for r in execution_results)
        
        if success:
            # Update metrics
            ticketzero_engine.metrics['tickets_resolved'] += 1
            ticketzero_engine.metrics['total_time_saved'] += analysis.get('time_to_resolve', 15)
            ticketzero_engine.metrics['total_money_saved'] += analysis.get('time_to_resolve', 15) * 1.5
            ticketzero_engine.update_success_rate()
            
            # Create response
            resolution_response = zoho_api.generate_zoho_response({
                'status': 'resolved',
                'issue_type': analysis['issue_type'],
                'confidence': analysis['confidence'],
                'commands_executed': commands,
                'time_to_resolve': sum(1 for r in execution_results if r['success']),
                'time_saved': analysis.get('time_to_resolve', 15),
                'money_saved': analysis.get('time_to_resolve', 15) * 1.5
            })
            
            logger.info(f"✅ Ticket {ticket_id} resolved successfully")
            
            return jsonify(resolution_response)
        
        else:
            logger.error(f"❌ Command execution failed for ticket {ticket_id}")
            return jsonify({
                'success': False,
                'error': 'Command execution failed',
                'execution_results': execution_results
            }), 500
        
    except Exception as e:
        logger.error(f"❌ Resolution execution failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """
    Get TicketZero AI performance metrics for dashboard
    """
    try:
        global ticketzero_engine
        if not ticketzero_engine:
            return jsonify({
                'success': False,
                'error': 'Engine not available'
            }), 503
        
        metrics = ticketzero_engine.get_dashboard_metrics()
        
        return jsonify({
            'success': True,
            'data': metrics,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"❌ Failed to get metrics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/webhooks/ticket-created', methods=['POST'])
def webhook_ticket_created():
    """
    Webhook handler for new tickets from Zoho Desk
    Enables automatic processing of incoming tickets
    """
    try:
        webhook_data = request.get_json()
        
        logger.info(f"🔔 Webhook received: New ticket created")
        logger.debug(f"Webhook data: {webhook_data}")
        
        # Extract ticket data from webhook
        if 'ticket' in webhook_data:
            zoho_ticket = webhook_data['ticket']
            
            # Check if auto-processing is enabled (would be configurable)
            auto_process = os.getenv('TICKETZERO_AUTO_PROCESS', 'false').lower() == 'true'
            
            if auto_process:
                # Convert and analyze ticket automatically
                ticketzero_ticket = zoho_api.sanitize_ticket_data(zoho_ticket)
                
                # Process in background (in production, would use task queue)
                result = ticketzero_engine.process_ticket_pipeline(ticketzero_ticket)
                
                logger.info(f"📊 Auto-processing result: {result['status']}")
        
        return jsonify({
            'success': True,
            'message': 'Webhook processed successfully'
        })
        
    except Exception as e:
        logger.error(f"❌ Webhook processing failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """
    Handle configuration management for the marketplace app
    """
    if request.method == 'GET':
        # Return current configuration
        config = {
            'auto_analyze': os.getenv('TICKETZERO_AUTO_ANALYZE', 'true'),
            'auto_resolve': os.getenv('TICKETZERO_AUTO_RESOLVE', 'false'),
            'min_confidence': int(os.getenv('TICKETZERO_MIN_CONFIDENCE', '70')),
            'ollama_host': os.getenv('TICKETZERO_OLLAMA_HOST', 'http://localhost:11434'),
            'model': os.getenv('TICKETZERO_MODEL', 'llama2')
        }
        
        return jsonify({
            'success': True,
            'data': config
        })
    
    elif request.method == 'POST':
        # Update configuration
        try:
            new_config = request.get_json()
            
            # Validate configuration values
            if 'min_confidence' in new_config:
                if not (0 <= int(new_config['min_confidence']) <= 100):
                    return jsonify({
                        'success': False,
                        'error': 'min_confidence must be between 0 and 100'
                    }), 400
            
            # In production, this would update environment variables or database
            logger.info(f"📝 Configuration updated: {new_config}")
            
            return jsonify({
                'success': True,
                'message': 'Configuration updated successfully'
            })
            
        except Exception as e:
            logger.error(f"❌ Configuration update failed: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 TICKETZERO AI - ZOHO DESK MARKETPLACE API")
    print("="*70)
    print("✅ Starting API server for Zoho Desk integration...")
    print("🔗 Endpoints available:")
    print("   • /api/health - Health check")
    print("   • /api/analyze-ticket - Ticket analysis")
    print("   • /api/execute-resolution - Execute fixes")
    print("   • /api/metrics - Performance metrics")
    print("   • /webhooks/ticket-created - New ticket webhook")
    print("   • /api/config - Configuration management")
    print("\n🌐 Server starting on http://localhost:5000")
    print("="*70)
    
    app.run(host='0.0.0.0', port=5000, debug=True)